rule VirusShareTrojanDownLoader4346565_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4346565_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "738b9fcf0f3a70565f478032bb950652d182c6cf8e738a42e048df91a6c15a37"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3 = "tell price" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}