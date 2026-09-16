rule sig_20161206_c0638bb935d4f8853751d8a7a2f39bfd {
  meta:
    description = "datamaliciousorder - file 20161206_c0638bb935d4f8853751d8a7a2f39bfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7df664650496d552f49b15ad3184c950507dc813b8eae5a4aef14b51fb007ba7"

  strings:
    $s1 = "var vYFs2 = new Function(\"s\", '{var vSz2 = new Date();vSz2[\"setUTCFullYear\"](\"2003\");if (vSz2.getUTCFullYear().toString(10" ascii
    $s2 = "var vYFs2 = new Function(\"s\", '{var vSz2 = new Date();vSz2[\"setUTCFullYear\"](\"2003\");if (vSz2.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vXc3 = s.split(\"##\"); return vXc3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}