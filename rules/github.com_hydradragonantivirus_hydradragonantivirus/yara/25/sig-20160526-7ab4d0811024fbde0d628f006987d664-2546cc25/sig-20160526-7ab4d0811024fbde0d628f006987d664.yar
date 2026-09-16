rule sig_20160526_7ab4d0811024fbde0d628f006987d664 {
  meta:
    description = "datamaliciousorder - file 20160526_7ab4d0811024fbde0d628f006987d664.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6c1ba71f13a0e09f98b68acf19b9558c8eb4d12ff8e0112223004094e98029"

  strings:
    $s1 = " rav\\n;\"rf2x\\\\\" = keppelg rav\\n;)0(]\"tAra\"+\"86x\\\\\"+\"c\"[gedotdarg = ecapsetihwxelfg rav;\"GVf\" = gedotdarg rav\\n;" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}