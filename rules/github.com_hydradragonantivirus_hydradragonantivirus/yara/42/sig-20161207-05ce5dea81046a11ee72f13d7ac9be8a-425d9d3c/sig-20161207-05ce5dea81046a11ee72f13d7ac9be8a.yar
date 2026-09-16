rule sig_20161207_05ce5dea81046a11ee72f13d7ac9be8a {
  meta:
    description = "datamaliciousorder - file 20161207_05ce5dea81046a11ee72f13d7ac9be8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1c2b81cf89085f1dce2daf5dc270be039f444d9454fe15e6f92725fcdddf3a0"

  strings:
    $s1 = "var vJKi3 = new Function(\"vCCs0\", '{return vCCs0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLh3 = new Function(\"vCC" ascii
    $s2 = " = new Date();vZj8[\"setUTCFullYear\"](\"2003\");if (vZj8.getUTCFullYear().toString(10) == \"2003\") {var vHVm1 = vCCs0.split(\"" ascii
    $s3 = " return vHVm1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJKi3 = new Function(\"vCCs0\", '{return vCCs0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLh3 = new Function(\"vCC" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}