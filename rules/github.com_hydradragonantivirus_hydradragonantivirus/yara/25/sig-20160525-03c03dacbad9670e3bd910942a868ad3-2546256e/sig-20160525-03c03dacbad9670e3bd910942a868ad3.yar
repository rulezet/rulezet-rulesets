rule sig_20160525_03c03dacbad9670e3bd910942a868ad3 {
  meta:
    description = "datamaliciousorder - file 20160525_03c03dacbad9670e3bd910942a868ad3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee481e0fabe34567c3a5f2861a728555bef76a291499131f374665f9e321d2fe"

  strings:
    $s1 = "pelt rav\\n;\"f4x\\\\56x\\\\47x\\\\\" = ecapsetihwxelft rav\\n;\"56x\\\\j26x\\\\\" = modnart rav\\n;\"47x\\\\c\" = deerdt rav\\n" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}