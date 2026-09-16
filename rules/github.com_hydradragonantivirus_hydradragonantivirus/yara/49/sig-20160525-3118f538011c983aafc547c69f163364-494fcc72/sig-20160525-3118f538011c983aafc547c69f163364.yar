rule sig_20160525_3118f538011c983aafc547c69f163364 {
  meta:
    description = "datamaliciousorder - file 20160525_3118f538011c983aafc547c69f163364.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ef2b706996d75c6652627f2b6df73ec03f413c90357ef96fd936fbccdae9251"

  strings:
    $s1 = "loci nruter{)dnenoisilloci(suidarelcitrapi noitcnuf\\n;\"PM54x\\\\T%\" = mi rav\\n;\"f2x\\\\%\" = gedotdari rav\\n;\"N34x\\\\43x" ascii
    $s2 = "n;\"t86x\\\\\" = keppelf rav\\n;\"a3x\\\\p47x\\\\\" = ecapsetihwxelff rav\\n;\"hf2x\\\\f2x\\\\\" = deerdf rav\\n;\"mf6x\\\\\" = " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}