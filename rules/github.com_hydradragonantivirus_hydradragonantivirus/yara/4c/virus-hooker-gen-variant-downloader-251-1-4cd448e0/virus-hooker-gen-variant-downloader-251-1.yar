rule Virus_Hooker_Gen_Variant_Downloader_251_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Variant.Downloader.251_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93b0b99d08c8e3598361c05dc106336cdbce954b4cd4f61ddb851403825f986e"

  strings:
    $s1 = "rYOT}[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}