rule VirusShareTrojanInject36111_21_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c176f607e4fa74adf107a43c13ebff55ed05482fee9c94353f1dff79924368af"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s3 = "Copyright (C) 2009 Secure By Design Inc" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}