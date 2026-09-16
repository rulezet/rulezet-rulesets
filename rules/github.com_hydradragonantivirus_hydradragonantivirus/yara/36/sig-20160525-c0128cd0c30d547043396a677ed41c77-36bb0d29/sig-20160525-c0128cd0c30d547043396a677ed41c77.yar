rule sig_20160525_c0128cd0c30d547043396a677ed41c77 {
  meta:
    description = "datamaliciousorder - file 20160525_c0128cd0c30d547043396a677ed41c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf0be5f1e5d818d958100c469022c8d29c1f639e3307a54b3f6618f99b07680"

  strings:
    $s1 = "ter{)mq(dnenoisillocq noitcnuf\\n;\"a47x\\\\s\" = gedotdarq rav\\n;\" t27x\\\\\" = keppelq rav\\n;\"tixen\\\\r\\\\\" = ecapsetih" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}