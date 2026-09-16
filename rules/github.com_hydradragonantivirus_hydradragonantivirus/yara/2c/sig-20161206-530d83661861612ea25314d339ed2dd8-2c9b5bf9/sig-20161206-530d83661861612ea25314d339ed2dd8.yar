rule sig_20161206_530d83661861612ea25314d339ed2dd8 {
  meta:
    description = "datamaliciousorder - file 20161206_530d83661861612ea25314d339ed2dd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8e1b9bb3ad77464b392f1e1a141aa716e26c344c307d0ea7397e21d7cac4cda"

  strings:
    $s1 = "var vXHg2 = new Function(\"s\", '{var vCn5 = new Date();vCn5[\"setUTCFullYear\"](\"2003\");if (vCn5.getUTCFullYear().toString(10" ascii
    $s2 = "var vXHg2 = new Function(\"s\", '{var vCn5 = new Date();vCn5[\"setUTCFullYear\"](\"2003\");if (vCn5.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vOFr1 = s.split(\"##\"); return vOFr1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vBt4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}