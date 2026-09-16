rule sig_20161206_e11d4cbbdd674305cb678cd7097dc475 {
  meta:
    description = "datamaliciousorder - file 20161206_e11d4cbbdd674305cb678cd7097dc475.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6d800786d29e6d4059344beb5eb08120e4bfab9a3228dff2792b36a0f02cf6f"

  strings:
    $s1 = "var vTi8 = new Function(\"s\", '{var vASe6 = new Date();vASe6[\"setUTCFullYear\"](\"2003\");if (vASe6.getUTCFullYear().toString(" ascii
    $s2 = "var vTi8 = new Function(\"s\", '{var vASe6 = new Date();vASe6[\"setUTCFullYear\"](\"2003\");if (vASe6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vKKh2 = s.split(\"##\"); return vKKh2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vPp1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}