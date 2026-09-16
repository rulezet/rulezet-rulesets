rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90773aee40dce54bd73ddd9dd8e921615c9f7423054a2e1fb1d60784ef427bcc"

  strings:
    $s1 = "Hello word" fullword ascii
    $s2 = "><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>" fullword ascii
    $s3 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
    $s4 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
    $s5 = "o word$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}