rule sig_20160525_0a0cab96038988853ffe2a59ca2643ba {
  meta:
    description = "datamaliciousorder - file 20160525_0a0cab96038988853ffe2a59ca2643ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4629bb54ca0b1a33807e0af1b19170dd30a2a87ee5732a604daa26fe274f83d"

  strings:
    $s1 = " rav\\n;\"rf2x\\\\\" = keppelg rav\\n;)0(]\"tAra\"+\"86x\\\\\"+\"c\"[gedotdarg = ecapsetihwxelfg rav;\"GVf\" = gedotdarg rav\\n;" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}