rule Virus_Hijack_Trojan_GenericKDZ_105924_133_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_133_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6e697c2cb15dfb6fb11f2872c2fd79a44fbcaf8c1e5d0feab8506779b628775"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}