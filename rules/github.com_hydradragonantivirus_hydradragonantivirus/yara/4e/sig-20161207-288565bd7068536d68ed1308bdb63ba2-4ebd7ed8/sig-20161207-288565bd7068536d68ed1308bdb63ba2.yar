rule sig_20161207_288565bd7068536d68ed1308bdb63ba2 {
  meta:
    description = "datamaliciousorder - file 20161207_288565bd7068536d68ed1308bdb63ba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cff9400643fc14dee4064ad965c4e3e70bdd3b6324a7661341227d161a3debe"

  strings:
    $s1 = "new Date();vKa5[\"setUTCFullYear\"](\"2003\");if (vKa5.getUTCFullYear().toString(10) == \"2003\") {var vHb9 = vJs8.split(\"####" ascii
    $s2 = "var vQy2 = new Function(\"vJs8\", '{return vJs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVSm1 = new Function(\"vJs8" ascii
    $s3 = "var vQy2 = new Function(\"vJs8\", '{return vJs8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVSm1 = new Function(\"vJs8" ascii
    $s4 = "rn vHb9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}