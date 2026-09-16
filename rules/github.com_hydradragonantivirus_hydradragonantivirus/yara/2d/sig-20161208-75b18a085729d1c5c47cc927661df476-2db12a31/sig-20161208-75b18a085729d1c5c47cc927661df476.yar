rule sig_20161208_75b18a085729d1c5c47cc927661df476 {
  meta:
    description = "datamaliciousorder - file 20161208_75b18a085729d1c5c47cc927661df476.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8f543b22db78c47f2e8c765b15dc89853a952602a5e27aabe34a6cc849b6e94"

  strings:
    $s1 = " = new Date();vBWh1[\"setUTC\"+\"FullYear\"](\"2003\");if (vBWh1.getUTCFullYear().toString(10) == \"2003\") {var vCf4 = vSEy9.sp" ascii
    $s2 = "var vCn0 = new Function(\"vSEy9\", '{return vSEy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQv0 = new Function(\"vSEy" ascii
    $s3 = "#\"); return vCf4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCn0 = new Function(\"vSEy9\", '{return vSEy9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQv0 = new Function(\"vSEy" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}