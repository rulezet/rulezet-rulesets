rule sig_20160525_ead5ef157b7d8efd69fd8768eb931118 {
  meta:
    description = "datamaliciousorder - file 20160525_ead5ef157b7d8efd69fd8768eb931118.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7bc7b07d91519194b93bf3007124a27c634cc8c64857ff6b6e7193d83f8ec35"

  strings:
    $s1 = "dark noitcnuf( + eixodk + ))(};imj nruter{)(mk noitcnuf( + rerednerj(]ime + rerednere + cthe[tpircSW = eixodb rav    \\n{\\n)sso" ascii
    $s2 = "c6x\\\\\" = imq rav\\n;)2(]\"tArah\"+\"36x\\\\\"+\"\"[rerednerq = eixodr rav;\"h3K\" = rerednerq rav\\n;\"e6x\\\\el\" = gsmr rav" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}