rule Virus_Hijack_Trojan_GenericKDZ_103285_34_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a86baa02228b9381cacb8cfa72069faeda208c47aade4be0ca85c66436b05c72"

  strings:
    $s1 = "url.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}