rule mal_macos_ventir_keylog: keylogger {
  meta:
    description = "Identify macOS Ventir backdoor's keylogger component."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.21"
    references  = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample      = "92667ebbd1bc05e1abd6078d7496c26e50353122bc71b89135f2c71bcad18440"
    DaysofYARA  = "80/100"

  strings:
    $s0 = "[command]"
    $s1 = "[option]"
    $s2 = "/Library/.local/.logfile"

    $keytab = { 61 73 64 66 68 67 7a 78 63 76 00 62 71 77 65 72 79 74 31 32 33 34 36 35 3d 39 37 2d 38 30 5d 6f 75 5b 69 70 0d 6c 6a 27 6b 3b 5c 2c 2f 6e 6d 2e 09 20 60 08 00 1b 00 00 00 00 00 00 00 00 00 00 00 2e 00 2a 00 2b 00 00 00 00 00 2f 0d 00 2d 00 00 00 30 31 32 33 34 35 36 37 38 39 }

    $fp = "/proc/self/exe"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of ($s*) and $keytab and
    not $fp
}