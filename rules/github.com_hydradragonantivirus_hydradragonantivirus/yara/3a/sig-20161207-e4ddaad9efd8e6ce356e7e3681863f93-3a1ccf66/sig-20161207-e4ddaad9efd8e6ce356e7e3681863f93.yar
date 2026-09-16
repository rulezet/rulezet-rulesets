rule sig_20161207_e4ddaad9efd8e6ce356e7e3681863f93 {
  meta:
    description = "datamaliciousorder - file 20161207_e4ddaad9efd8e6ce356e7e3681863f93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4d633d60ac80843aff6359b948ce59c71aef1440f5e508a98f62993ae671248"

  strings:
    $s1 = "var vQh3 = new Function(\"vRx6\", '{return vRx6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFGt4 = new Function(\"vRx6" ascii
    $s2 = " new Date();vZUm3[\"setUTCFullYear\"](\"2003\");if (vZUm3.getUTCFullYear().toString(10) == \"2003\") {var vEMk1 = vRx6.split(\"#" ascii
    $s3 = "var vQh3 = new Function(\"vRx6\", '{return vRx6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFGt4 = new Function(\"vRx6" ascii
    $s4 = "return vEMk1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}