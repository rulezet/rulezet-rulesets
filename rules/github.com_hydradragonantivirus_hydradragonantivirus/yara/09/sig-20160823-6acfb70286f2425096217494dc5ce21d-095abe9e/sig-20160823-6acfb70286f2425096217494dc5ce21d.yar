rule sig_20160823_6acfb70286f2425096217494dc5ce21d {
  meta:
    description = "datamaliciousorder - file 20160823_6acfb70286f2425096217494dc5ce21d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e2cd7e36cc69c92797f96bff251f014bb40422e6b38e6b2fff20242a92b2247"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}