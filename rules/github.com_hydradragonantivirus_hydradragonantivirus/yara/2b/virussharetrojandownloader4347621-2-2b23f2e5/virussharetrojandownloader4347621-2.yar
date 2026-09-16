rule VirusShareTrojanDownLoader4347621_2 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4347621_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f75f41f8bdbbbcbe5cdd254d3f388bc9f96afd15e2caf603fdfac0ce109e92b9"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}