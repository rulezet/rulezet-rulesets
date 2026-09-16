rule sig_20160525_d753f5c1a0d439f922feee1bbd0292a9 {
  meta:
    description = "datamaliciousorder - file 20160525_d753f5c1a0d439f922feee1bbd0292a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9e7d4fa514049ccad0099eb8ea583295ef35b3cfa0f70df9a11665819835dd"

  strings:
    $s1 = "lock rav\\n;\"t76x\\\\e6x\\\\\" = mk rav\\n;)1(]\"tAra\"+\"86x\\\\\"+\"c\"[suidarelcitrapk = gedotdark rav;\"f9hE\" = suidarelci" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}