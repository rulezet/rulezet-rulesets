rule VirusShareTrojanDownLoader4345326_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4345326_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b80d31179aecd02ef1954f7138c12dda11a87c7a34c94cd72a005bae710ba802"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3 = "tell price" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}