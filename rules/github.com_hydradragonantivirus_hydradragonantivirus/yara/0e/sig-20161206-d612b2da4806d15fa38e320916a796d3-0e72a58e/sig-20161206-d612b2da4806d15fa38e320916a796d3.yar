rule sig_20161206_d612b2da4806d15fa38e320916a796d3 {
  meta:
    description = "datamaliciousorder - file 20161206_d612b2da4806d15fa38e320916a796d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c353fe08c27443f8b5cd13d084dcfd4e930507b2bc20ba4f07aaab1fe587e680"

  strings:
    $s1 = "var vNLz5 = new Function(\"s\", '{var vTc4 = new Date();vTc4[\"setUTCFullYear\"](\"2003\");if (vTc4.getUTCFullYear().toString(10" ascii
    $s2 = "var vNLz5 = new Function(\"s\", '{var vTc4 = new Date();vTc4[\"setUTCFullYear\"](\"2003\");if (vTc4.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vAVm8 = s.split(\"##\"); return vAVm8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vRKk2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}