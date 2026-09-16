rule mal_macos_ventir_dropper: dropper {
  meta:
    description = "Identify macOS Ventir backdoor dropper."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.20"
    references  = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample      = "59539ff9af82c0e4e73809a954cf2776636774e6c42c281f3b0e5f1656e93679"
    DaysofYARA  = "79/100"

  strings:
    $s0 = "/proc/self/exe"
    $s1 = "/bin/mv -f %s/updated.kext /System/Library/Extensions/updated.kext"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}