rule sig_20161207_9d51c57fba7193307305f67c31adb3d4 {
  meta:
    description = "datamaliciousorder - file 20161207_9d51c57fba7193307305f67c31adb3d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31f6bc01ce3c4b37488f886aac9b53a6889dbaa2520b66ea47a8b7a8520fa93e"

  strings:
    $s1 = " new Date();vEZd5[\"setUTCFullYear\"](\"2003\");if (vEZd5.getUTCFullYear().toString(10) == \"2003\") {var vGf3 = vNt8.split(\"##" ascii
    $s2 = "var vSMr9 = new Function(\"vNt8\", '{return vNt8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAn6 = new Function(\"vNt8" ascii
    $s3 = "eturn vGf3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSMr9 = new Function(\"vNt8\", '{return vNt8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAn6 = new Function(\"vNt8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}