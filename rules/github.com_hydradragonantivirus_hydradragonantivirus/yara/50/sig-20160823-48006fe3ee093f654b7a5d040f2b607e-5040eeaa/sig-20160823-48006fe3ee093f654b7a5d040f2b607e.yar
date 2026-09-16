rule sig_20160823_48006fe3ee093f654b7a5d040f2b607e {
  meta:
    description = "datamaliciousorder - file 20160823_48006fe3ee093f654b7a5d040f2b607e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6c2a2c210d594b1991a20974e147422fe2f14479ef2ec2bcf12516ccbc0f056"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}