rule sig_20161206_215af86e4e9c0026f83db7d477d598d7 {
  meta:
    description = "datamaliciousorder - file 20161206_215af86e4e9c0026f83db7d477d598d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83be8ddeb821e7ff8009fea3562d03fe7175a7794507861de44a905c38a0645d"

  strings:
    $s1 = "var vTe0 = new Function(\"s\", '{var vGk4 = new Date();vGk4[\"setUTCFullYear\"](\"2003\");if (vGk4.getUTCFullYear().toString(10)" ascii
    $s2 = "var vTe0 = new Function(\"s\", '{var vGk4 = new Date();vGk4[\"setUTCFullYear\"](\"2003\");if (vGk4.getUTCFullYear().toString(10)" ascii
    $s3 = "function vYl3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vHVk1 = s.split(\"##\"); return vHVk1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}