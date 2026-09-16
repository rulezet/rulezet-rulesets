rule file_macho_header {
  meta:
    description   = "Matches Mach-O file headers as uint32"
    last_modified = "2024-01-03"
    author        = "@petermstewart"
    DaysofYara    = "3/100"

  condition:
    uint32(0) == 0xfeedface or      uint32(0) == 0xcefaedfe or      uint32(0) == 0xfeedfacf or      uint32(0) == 0xcffaedfe or      uint32(0) == 0xcafebabe or      uint32(0) == 0xbebafeca  }