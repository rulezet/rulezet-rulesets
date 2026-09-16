rule sig_20160525_a525e1ce47076612991820cfcddbfc46 {
  meta:
    description = "datamaliciousorder - file 20160525_a525e1ce47076612991820cfcddbfc46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8563454b9e2f25bdb830896d719fcf6ff00eab860ed24b11399fde3413d856d"

  strings:
    $s1 = "\\c6x\\\\\" = sdnetu rav\\n;\"ht76x\\\\n\" = ssorcau rav\\n;\"gn56x\\\\l\" = tsilslianbmuhtou rav\\n;\"h47x\\\\\" = cthu rav'[\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}