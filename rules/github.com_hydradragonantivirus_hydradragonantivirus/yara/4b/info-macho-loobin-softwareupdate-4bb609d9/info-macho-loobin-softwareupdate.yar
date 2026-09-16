rule INFO_Macho_LOObin_softwareupdate {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin softwareupdate"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "softwareupdate" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      )
    and all of them
}