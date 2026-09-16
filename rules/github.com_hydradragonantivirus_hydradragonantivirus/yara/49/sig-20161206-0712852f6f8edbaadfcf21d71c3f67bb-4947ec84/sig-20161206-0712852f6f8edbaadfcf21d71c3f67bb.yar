rule sig_20161206_0712852f6f8edbaadfcf21d71c3f67bb {
  meta:
    description = "datamaliciousorder - file 20161206_0712852f6f8edbaadfcf21d71c3f67bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8be821065a89c7be5a9b7329600833f10e2526bfa4306f60b6a3262708b76732"

  strings:
    $s1 = "var vZYn5 = new Function(\"s\", '{var vYOu5 = new Date();vYOu5[\"setUTCFullYear\"](\"2003\");if (vYOu5.getUTCFullYear().toString" ascii
    $s2 = "var vZYn5 = new Function(\"s\", '{var vYOu5 = new Date();vYOu5[\"setUTCFullYear\"](\"2003\");if (vYOu5.getUTCFullYear().toString" ascii
    $s3 = "function vBb2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vOPk9 = s.split(\"##\"); return vOPk9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}