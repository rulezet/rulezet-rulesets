rule sig_20161206_51cb58c3117769b0613243ba2bd5ee6c {
  meta:
    description = "datamaliciousorder - file 20161206_51cb58c3117769b0613243ba2bd5ee6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48a6feebe37a1c0f1b85db84aed39f10590d8895940a4c94ce9be9147eea520"

  strings:
    $s1 = "var vFg4 = new Function(\"s\", '{var vHw5 = new Date();vHw5[\"setUTCFullYear\"](\"2003\");if (vHw5.getUTCFullYear().toString(10)" ascii
    $s2 = "var vFg4 = new Function(\"s\", '{var vHw5 = new Date();vHw5[\"setUTCFullYear\"](\"2003\");if (vHw5.getUTCFullYear().toString(10)" ascii
    $s3 = "function vZLo9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vTe8 = s.split(\"##\"); return vTe8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}