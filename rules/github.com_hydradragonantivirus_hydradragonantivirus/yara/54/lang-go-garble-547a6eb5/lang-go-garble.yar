rule lang_go_garble {
  meta:
    description   = "Identify a Go binary obfuscated with Garble"
    author        = "@shellcromancer"
    version       = "1.0"
    last_modified = "2023.01.11"
    reference     = "https://github.com/burrowers/garble"
    DaysofYARA    = "11/100"

  strings:
    $GoBuildID = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
    $runtime   = "runtime."
    $reflect   = "reflect."
        $func      = /\*func\(\) \*?[a-zA-Z0-9_]{5,20}\.[a-zA-Z0-9_]{4,19}/

  condition:
    (
      int16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    not $GoBuildID and
    #runtime > 4 and
    #reflect > 4 and
    $func
}