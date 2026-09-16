rule sig_20160525_2a55bdb09a41c1458b562922ca94b5b5 {
  meta:
    description = "datamaliciousorder - file 20160525_2a55bdb09a41c1458b562922ca94b5b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "011735dd6037d52b5a340865b4fbe130400982d352fe4e36f7df4f37f8dbc7af"

  strings:
    $s1 = "uter{)sdneth(deerdh noitcnuf;};modnarh nruter{)modnarh(ecapsetihwxelfh noitcnuf;};gedotdarh nruter{)gedotdarh(mh noitcnuf;};suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}