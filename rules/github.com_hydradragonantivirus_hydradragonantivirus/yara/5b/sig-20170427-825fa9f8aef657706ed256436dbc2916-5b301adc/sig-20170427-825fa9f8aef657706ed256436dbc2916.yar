rule sig_20170427_825fa9f8aef657706ed256436dbc2916 {
  meta:
    description = "datamaliciousorder - file 20170427_825fa9f8aef657706ed256436dbc2916.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae93fdf5c49361d645601ffa45a6857d0024dfcfe9e53f54acfa0f2c54a068c0"

  strings:
    $s1 = "function CPlJORTkprswALXzxq(tbKUknhrpFTqzELeVi, gkDItGvrcwuOTFRLyen) { " fullword ascii
    $s2 = "if (DoyghszCStTplMmUqdX() == false) {" fullword ascii
    $s3 = "return tbKUknhrpFTqzELeVi.split(gkDItGvrcwuOTFRLyen).join(\"\"); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}