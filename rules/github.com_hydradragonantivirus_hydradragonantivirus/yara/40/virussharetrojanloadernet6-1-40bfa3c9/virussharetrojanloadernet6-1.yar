rule VirusShareTrojanLoaderNET6_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanLoaderNET6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "642fce13ab9049355d8059bce6ad9819c470782c19249b23306ffb883aaa58ca"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "Window Security Startup.exe" fullword wide
    $s3 = "Window Security Startup" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}