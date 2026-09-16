rule sig_20161206_656fef47d656ccc221a84318f1834d80 {
  meta:
    description = "datamaliciousorder - file 20161206_656fef47d656ccc221a84318f1834d80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c5dca355657254d5651647b6166f2a6bfd8c9d1ee77b6e52fdb8a03d1a8b1f4"

  strings:
    $s1 = "var vBz0 = new Function(\"s\", '{var vAu8 = new Date();vAu8[\"setUTCFullYear\"](\"2003\");if (vAu8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vBz0 = new Function(\"s\", '{var vAu8 = new Date();vAu8[\"setUTCFullYear\"](\"2003\");if (vAu8.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vNLv5 = s.split(\"##\"); return vNLv5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vXFm3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}