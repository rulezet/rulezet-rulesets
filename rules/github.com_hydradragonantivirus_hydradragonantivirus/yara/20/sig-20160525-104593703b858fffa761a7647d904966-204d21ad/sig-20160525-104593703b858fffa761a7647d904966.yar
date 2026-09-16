rule sig_20160525_104593703b858fffa761a7647d904966 {
  meta:
    description = "datamaliciousorder - file 20160525_104593703b858fffa761a7647d904966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fb3922a6fec3036445a4b5e2156e364022fea9509c0ce8b8ad3758a42fc382a"

  strings:
    $s1 = "eppelf nruter{)(ecapsetihwxelff noitcnuf( + gedotdarf + mf+suidarelcitrapf ,gsmf + eixodf+rerednere + cthe+ssorcae+sdnete + deer" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}