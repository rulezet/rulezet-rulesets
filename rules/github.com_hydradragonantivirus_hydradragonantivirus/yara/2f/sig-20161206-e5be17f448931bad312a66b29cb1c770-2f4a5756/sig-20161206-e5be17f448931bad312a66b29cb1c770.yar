rule sig_20161206_e5be17f448931bad312a66b29cb1c770 {
  meta:
    description = "datamaliciousorder - file 20161206_e5be17f448931bad312a66b29cb1c770.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a6a33e0ecd6de5ed368e3f68fba7fffc5f35a8e5892d63552e4523f9f2747cd"

  strings:
    $s1 = "var vHEi7 = new Function(\"s\", '{var vEXz9 = new Date();vEXz9[\"setUTCFullYear\"](\"2003\");if (vEXz9.getUTCFullYear().toString" ascii
    $s2 = "var vHEi7 = new Function(\"s\", '{var vEXz9 = new Date();vEXz9[\"setUTCFullYear\"](\"2003\");if (vEXz9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vFh3 = s.split(\"##\"); return vFh3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vPGk5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}