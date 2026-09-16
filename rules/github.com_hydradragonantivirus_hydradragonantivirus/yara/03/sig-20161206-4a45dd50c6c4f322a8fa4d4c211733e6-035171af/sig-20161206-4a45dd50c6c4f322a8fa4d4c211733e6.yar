rule sig_20161206_4a45dd50c6c4f322a8fa4d4c211733e6 {
  meta:
    description = "datamaliciousorder - file 20161206_4a45dd50c6c4f322a8fa4d4c211733e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc8ad4110831bb6d4e77f7208913e4c66ac600821c78048248aaee40324aef1e"

  strings:
    $s1 = "var vWVt9 = new Function(\"s\", '{var vJHy3 = new Date();vJHy3[\"setUTCFullYear\"](\"2003\");if (vJHy3.getUTCFullYear().toString" ascii
    $s2 = "var vWVt9 = new Function(\"s\", '{var vJHy3 = new Date();vJHy3[\"setUTCFullYear\"](\"2003\");if (vJHy3.getUTCFullYear().toString" ascii
    $s3 = "function vAt2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vJCh5 = s.split(\"##\"); return vJCh5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}