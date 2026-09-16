rule sig_20161207_9cc1d373bc2255d911740f3989ba89ef {
  meta:
    description = "datamaliciousorder - file 20161207_9cc1d373bc2255d911740f3989ba89ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad4acecfe3eb2ac784f776c905bac041a558abd7994351bdb8514fb4a811dfcf"

  strings:
    $s1 = " new Date();vCGs0[\"setUTCFullYear\"](\"2003\");if (vCGs0.getUTCFullYear().toString(10) == \"2003\") {var vUDs9 = vHu2.split(\"#" ascii
    $s2 = "var vXi3 = new Function(\"vHu2\", '{return vHu2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGKe1 = new Function(\"vHu2" ascii
    $s3 = "var vXi3 = new Function(\"vHu2\", '{return vHu2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGKe1 = new Function(\"vHu2" ascii
    $s4 = "return vUDs9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}