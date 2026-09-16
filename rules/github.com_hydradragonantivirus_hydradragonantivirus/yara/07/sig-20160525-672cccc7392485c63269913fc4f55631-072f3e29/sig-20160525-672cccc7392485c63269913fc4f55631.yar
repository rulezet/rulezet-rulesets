rule sig_20160525_672cccc7392485c63269913fc4f55631 {
  meta:
    description = "datamaliciousorder - file 20160525_672cccc7392485c63269913fc4f55631.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8e98d4b40cc5bdebd2dc6bcfe7fd03bccc4d840726a05b96289491f112317d3"

  strings:
    $s1 = "oo rav\\n;\"13x\\\\-sw\" = ctho rav\\n;\"253x\\\\2\" = rerednero rav\\n;\"t96x\\\\27x\\\\75x\\\\\" = eixodp rav\\n;\"xe45x\\\\e" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}