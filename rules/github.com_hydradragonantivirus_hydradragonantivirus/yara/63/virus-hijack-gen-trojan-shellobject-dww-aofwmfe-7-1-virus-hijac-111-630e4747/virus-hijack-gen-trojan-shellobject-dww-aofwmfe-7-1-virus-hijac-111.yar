rule _Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_7_1_Virus_Hijac_111 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8X@aSb8tSc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au4JtZd_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aSgChKg_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@amBwvTb_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3a371eeed003132da38f47c7f42f199cac54e2e605cfa01d2ca5fc45261b6d7"
    hash2       = "128bf0496985fbf2f5e196657b045ef9af4e3c394fc9512a9f97f79628a86412"
    hash3       = "aec675922d2efa71fa895d25335f13dc14b0949ded2b5151a19a1a826b7e53ec"
    hash4       = "8e16b431914741e0bcf26b209fdf85983505326f086307c7caebfb08e01455a7"
    hash5       = "0b5a763e85e6b6f2fae0ba5051194db7000704b099a57acd55a7bc5d67ece209"
    hash6       = "75dec25f1d2860c16fe0c242fd7dc4249627391802ef31fe15c2dfc2a2be7e4e"
    hash7       = "2a11b3c885ff0b7bb54b8d115b5056b84b68667d2c2e8279905e39d348882103"

  strings:
    $s1 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"" ascii
    $s2 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"" ascii
    $s3 = "//schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body>" fullword ascii
    $s4 = "<server xmlns=\"urn:schemas-microsoft-com:WMPNSSRME-1-0/\">" fullword ascii
    $s5 = "<manufacturer>Microsoft Corporation</manufacturer>" fullword wide
    $s6 = "<Result %ls>" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}