rule Virus_Hijack_Trojan_GenericKDZ_103285_296 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_296.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8258e298cab8ebe8802d9044a62b34082b63984233f8576025fda1307186450f"

  strings:
    $s1 = "MEdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}