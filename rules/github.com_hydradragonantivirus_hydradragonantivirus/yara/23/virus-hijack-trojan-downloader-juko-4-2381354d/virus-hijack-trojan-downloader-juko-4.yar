rule Virus_Hijack_Trojan_Downloader_JUKO_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Downloader.JUKO_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8a711bcce7a39dfa6aafe14d5340fb89492a2c18a25caea08deb10d641064b4"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}