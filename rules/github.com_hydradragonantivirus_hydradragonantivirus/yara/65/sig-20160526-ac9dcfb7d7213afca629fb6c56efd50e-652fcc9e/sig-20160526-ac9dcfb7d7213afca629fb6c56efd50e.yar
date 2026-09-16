rule sig_20160526_ac9dcfb7d7213afca629fb6c56efd50e {
  meta:
    description = "datamaliciousorder - file 20160526_ac9dcfb7d7213afca629fb6c56efd50e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2907b8179d6776522f2e5125652d37fe69027e63961aeba59df54b0d02690cb"

  strings:
    $s1 = "\\n;\"Ff6x\\\\45x\\\\56x\\\\\" = l7fAUXLNE rav\\n;\"ec6x\\\\i\" = r8kOZMEDH rav\\n;\"esoc6x\\\\c\" = r0pDORJQW rav'[\"split\"]('" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}