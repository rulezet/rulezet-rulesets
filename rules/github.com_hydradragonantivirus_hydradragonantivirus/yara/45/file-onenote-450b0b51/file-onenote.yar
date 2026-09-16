rule file_onenote {
  meta:
    description = "Identify OneNote "
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.01.20"
    reference   = "https://interoperability.blob.core.windows.net/files/MS-ONE/%5bMS-ONE%5d.pdf"
    DaysofYARA  = "20/100"

  condition:
    uint32be(0) == 0xE4525C7B
}