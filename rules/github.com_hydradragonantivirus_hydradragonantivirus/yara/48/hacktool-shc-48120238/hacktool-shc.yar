rule hacktool_shc {
  meta:
    description   = "Identify ELF executables built with the shc compiler"
    author        = "@shellcromancer"
    version       = "1.1"
    last_modified = "2023.02.01"
    reference     = "https://neurobin.org/projects/softwares/unix/shc/"
    reference     = "https://asec.ahnlab.com/en/45182/"
    sample        = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
    DaysofYARA    = "22/100"
    DaysofYARA    = "32/100"

  strings:
    $s1 = "neither argv[0] nor"
    $s2 = "%s%s%s: %s"

    $default_expiry = "jahidulhamid@yahoo.com"

  condition:
    (
      int16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    2 of them
}