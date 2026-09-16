rule sig_20161208_5ab82bb08daebc1d43271d756fcf11a0 {
  meta:
    description = "datamaliciousorder - file 20161208_5ab82bb08daebc1d43271d756fcf11a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e2c76c8dda001e47395c9b09fb6027c7602cc3d877132a1aef312d0ad682121"

  strings:
    $s1 = "= new Date();vJp9[\"setUTC\"+\"FullYear\"](\"2003\");if (vJp9.getUTCFullYear().toString(10) == \"2003\") {var vCPb3 = vFSm1.spli" ascii
    $s2 = "var vUk1 = new Function(\"vFSm1\", '{return vFSm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHp2 = new Function(\"vFSm" ascii
    $s3 = "var vUk1 = new Function(\"vFSm1\", '{return vFSm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHp2 = new Function(\"vFSm" ascii
    $s4 = "); return vCPb3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}