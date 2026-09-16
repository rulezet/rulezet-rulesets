rule sig_20161207_168d04b113beb480ace37b4cd4cffe8e {
  meta:
    description = "datamaliciousorder - file 20161207_168d04b113beb480ace37b4cd4cffe8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db0cccbea36c801802bbc315c213e535d9624a2f09a3471bdd01e3be6eae1608"

  strings:
    $s1 = " new Date();vEl3[\"setUTCFullYear\"](\"2003\");if (vEl3.getUTCFullYear().toString(10) == \"2003\") {var vTs0 = vKv3.split(\"####" ascii
    $s2 = "var vNVo4 = new Function(\"vKv3\", '{return vKv3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVCl5 = new Function(\"vKv3" ascii
    $s3 = "urn vTs0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNVo4 = new Function(\"vKv3\", '{return vKv3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVCl5 = new Function(\"vKv3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}