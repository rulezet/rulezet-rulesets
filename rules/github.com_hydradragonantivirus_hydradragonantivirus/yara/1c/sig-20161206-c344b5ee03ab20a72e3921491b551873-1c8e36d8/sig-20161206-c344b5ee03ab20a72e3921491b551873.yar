rule sig_20161206_c344b5ee03ab20a72e3921491b551873 {
  meta:
    description = "datamaliciousorder - file 20161206_c344b5ee03ab20a72e3921491b551873.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7878977f39f10614a7b2475a8cdd8ce33e769269eed16c0acd63c95d2c54c83d"

  strings:
    $s1 = "var vWk7 = new Function(\"s\", '{var vBDa0 = new Date();vBDa0[\"setUTCFullYear\"](\"2003\");if (vBDa0.getUTCFullYear().toString(" ascii
    $s2 = "var vWk7 = new Function(\"s\", '{var vBDa0 = new Date();vBDa0[\"setUTCFullYear\"](\"2003\");if (vBDa0.getUTCFullYear().toString(" ascii
    $s3 = "function vMVt6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vQd3 = s.split(\"##\"); return vQd3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}