rule sig_20161206_d212c363bc9072d03a829daba813fe44 {
  meta:
    description = "datamaliciousorder - file 20161206_d212c363bc9072d03a829daba813fe44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc236bdc182b45a7f7fed4c2db66ff377b57395912c786467bfd322fe1aec874"

  strings:
    $s1 = "var vFZm8 = new Function(\"s\", '{var vEGx4 = new Date();vEGx4[\"setUTCFullYear\"](\"2003\");if (vEGx4.getUTCFullYear().toString" ascii
    $s2 = "var vFZm8 = new Function(\"s\", '{var vEGx4 = new Date();vEGx4[\"setUTCFullYear\"](\"2003\");if (vEGx4.getUTCFullYear().toString" ascii
    $s3 = "function vNJx7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vIo9 = s.split(\"##\"); return vIo9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}