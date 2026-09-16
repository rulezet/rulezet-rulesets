rule sig_20160823_7943b2f5b9a0c70b533eb63eb57f4e1f {
  meta:
    description = "datamaliciousorder - file 20160823_7943b2f5b9a0c70b533eb63eb57f4e1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "697ae96247df64e432c7a693649816dda5bfd5a6db3948f733f25444733eea08"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}