rule sig_20160823_229b227ea846ddb7f4f4cb89b217c8bd {
  meta:
    description = "datamaliciousorder - file 20160823_229b227ea846ddb7f4f4cb89b217c8bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1dfe60f4d8a925a7358b45ba1352cbdeff0ab94a03fc397f11a187df7db602"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}