rule SUSP_LNK_Network_CloudServices_OneDrive_API {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $ = "api.live.com" ascii wide

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}