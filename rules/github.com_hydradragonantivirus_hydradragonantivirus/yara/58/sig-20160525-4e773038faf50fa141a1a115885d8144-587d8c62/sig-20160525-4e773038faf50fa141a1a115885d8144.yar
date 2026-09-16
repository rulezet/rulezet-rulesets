rule sig_20160525_4e773038faf50fa141a1a115885d8144 {
  meta:
    description = "datamaliciousorder - file 20160525_4e773038faf50fa141a1a115885d8144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c18fe27799984dd9deb2afa12bdcd070145da19c894af8a1d0bc34f1b350b5c2"

  strings:
    $s1 = "lslianbmuhtok noitcnuf\\n;\"etir77x\\\\\" = rerednerk rav\\n;\"37x\\\\56x\\\\R\" = eixodl rav\\n;\"o07x\\\\\" = gsml rav\\n;\"oB" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}