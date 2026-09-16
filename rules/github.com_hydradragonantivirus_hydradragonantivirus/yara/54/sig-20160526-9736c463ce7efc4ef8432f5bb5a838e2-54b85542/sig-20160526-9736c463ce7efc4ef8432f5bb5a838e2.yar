rule sig_20160526_9736c463ce7efc4ef8432f5bb5a838e2 {
  meta:
    description = "datamaliciousorder - file 20160526_9736c463ce7efc4ef8432f5bb5a838e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c2f72e7274b39770113a2dec910408b6fe86b1cf08a11ffe7bb44aea5a416d"

  strings:
    $s1 = "i64x\\\\o\" = m4uGAUKLN rav\\n;\"ec6x\\\\\" = v6vOOZYED rav\\n;\"f6x\\\\lc\" = w9jJAFDOR rav\\n;\"56x\\\\s\" = b4vPCCNHP rav'[\"" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}