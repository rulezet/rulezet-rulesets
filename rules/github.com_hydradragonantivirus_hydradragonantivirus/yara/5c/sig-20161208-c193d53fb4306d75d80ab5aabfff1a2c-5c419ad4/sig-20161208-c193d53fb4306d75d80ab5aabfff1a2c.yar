rule sig_20161208_c193d53fb4306d75d80ab5aabfff1a2c {
  meta:
    description = "datamaliciousorder - file 20161208_c193d53fb4306d75d80ab5aabfff1a2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a757ea25cf4be62552370e766eac034fe2c02ad5c2d1793bb9a5f88530e055f"

  strings:
    $s1 = "var vOe4 = new Function(\"vBXw2\", '{return vBXw2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGn6 = new Function(\"vBXw" ascii
    $s2 = " = new Date();vKDn3[\"setUTC\"+\"FullYear\"](\"2003\");if (vKDn3.getUTCFullYear().toString(10) == \"2003\") {var vUk6 = vBXw2.sp" ascii
    $s3 = "var vOe4 = new Function(\"vBXw2\", '{return vBXw2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGn6 = new Function(\"vBXw" ascii
    $s4 = "#\"); return vUk6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}