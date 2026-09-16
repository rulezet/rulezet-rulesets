rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_36_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_36_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe6ec55eb383a61725615537de96e54f118f50a34148acab96032ed92ebcf2ce"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}