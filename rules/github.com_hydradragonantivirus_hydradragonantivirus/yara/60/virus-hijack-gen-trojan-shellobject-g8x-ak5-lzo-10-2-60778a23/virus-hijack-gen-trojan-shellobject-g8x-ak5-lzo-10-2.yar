rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e05f2595953a42be953135c6b7c07cd21d8afc63450413728cebd0952332c39"

  strings:
    $s1 = "C:\\Program Files (x86)\\adobe\\Acrobat Reader DC\\Reader\\AcroLayoutRecognizer\\AcroLayoutRecognizer.exe" fullword ascii
    $s2 = "Adobe .com/AcrobatUpd812" fullword ascii
    $s3 = "\\My Shared Folder" fullword ascii
    $s4 = "ActiveMovie Control" fullword ascii
    $s5 = "AM1.0 QT PlugIn patch" fullword ascii
    $s6 = "ActiveMovie File Types" fullword ascii
    $s7 = "ZAM1.0 QT PlugIn patch" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}