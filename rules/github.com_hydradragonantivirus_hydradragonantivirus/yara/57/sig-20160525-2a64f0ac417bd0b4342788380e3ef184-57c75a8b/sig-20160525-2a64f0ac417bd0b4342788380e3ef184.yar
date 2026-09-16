rule sig_20160525_2a64f0ac417bd0b4342788380e3ef184 {
  meta:
    description = "datamaliciousorder - file 20160525_2a64f0ac417bd0b4342788380e3ef184.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2feb49d80fad3757382eeffdf8d34cc31b1ab1cc08093251db0aa63ee7288187"

  strings:
    $s1 = "dark noitcnuf( + eixodk + ))(};imj nruter{)(mk noitcnuf( + rerednerj(]ime + rerednere + cthe[tpircSW = eixodb rav    \\n{\\n)sso" ascii
    $s2 = "f6x\\\\T\" = suidarelcitrapp rav\\n;\"56x\\\\liF\" = dnenoisillocp rav\\n;\"56x\\\\sf6x\\\\lc\" = mp rav\\n;\"n57x\\\\25x\\\\\" " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}