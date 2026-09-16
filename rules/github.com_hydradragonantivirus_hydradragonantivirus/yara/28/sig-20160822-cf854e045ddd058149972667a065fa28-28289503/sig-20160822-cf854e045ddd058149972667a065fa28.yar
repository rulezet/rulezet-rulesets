rule sig_20160822_cf854e045ddd058149972667a065fa28 {
  meta:
    description = "datamaliciousorder - file 20160822_cf854e045ddd058149972667a065fa28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce64c9ef01069cc29317367231b7d902c5525ad216f199e9ecd89f479ede6a9"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}