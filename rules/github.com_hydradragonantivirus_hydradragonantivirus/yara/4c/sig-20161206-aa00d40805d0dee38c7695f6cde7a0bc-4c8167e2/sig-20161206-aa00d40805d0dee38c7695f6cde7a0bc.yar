rule sig_20161206_aa00d40805d0dee38c7695f6cde7a0bc {
  meta:
    description = "datamaliciousorder - file 20161206_aa00d40805d0dee38c7695f6cde7a0bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f18a6adbeec24709b77f95a52d023ad1a5dc99d5b3bdc9326c58d0b387d3a722"

  strings:
    $s1 = "var vCGz9 = new Function(\"s\", '{var vPCk2 = new Date();vPCk2[\"setUTCFullYear\"](\"2003\");if (vPCk2.getUTCFullYear().toString" ascii
    $s2 = "var vCGz9 = new Function(\"s\", '{var vPCk2 = new Date();vPCk2[\"setUTCFullYear\"](\"2003\");if (vPCk2.getUTCFullYear().toString" ascii
    $s3 = "function vUXd5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vXXf2 = s.split(\"##\"); return vXXf2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}