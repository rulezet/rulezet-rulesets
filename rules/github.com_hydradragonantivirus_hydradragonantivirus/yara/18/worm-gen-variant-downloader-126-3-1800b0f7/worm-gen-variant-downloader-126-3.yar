rule Worm_Gen_Variant_Downloader_126_3 {
  meta:
    description = "datamaliciousorder - file Worm_Gen.Variant.Downloader.126_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ada04b9d9b0611f4ee1ec1055647af989b2b30dc41e84b75be1bd479a16ea7dd"

  strings:
    $s1 = "Caffeina" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}