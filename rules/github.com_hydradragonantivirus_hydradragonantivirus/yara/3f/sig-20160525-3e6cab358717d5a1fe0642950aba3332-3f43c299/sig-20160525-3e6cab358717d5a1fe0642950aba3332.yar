rule sig_20160525_3e6cab358717d5a1fe0642950aba3332 {
  meta:
    description = "datamaliciousorder - file 20160525_3e6cab358717d5a1fe0642950aba3332.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7157d004841a95caadb8afc4d5e910a3a7f84d8708a0ba19b179a6170dad8a7"

  strings:
    $s1 = "43x\\\\\" = gedotdarb rav\\n;\"t86x\\\\\" = keppelb rav\\n;\"p47x\\\\\" = ecapsetihwxelfb rav\\n;\"f2x\\\\f2x\\\\:\" = modnarb r" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}