rule sig_20161206_73918eefcb94dc68184d627c62997f36 {
  meta:
    description = "datamaliciousorder - file 20161206_73918eefcb94dc68184d627c62997f36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08c4feda5df5a0ec86ff6920d4009bf6b3e7f1bb327e5ae2f08f14b5e10c5020"

  strings:
    $s1 = "var vCYb5 = new Function(\"s\", '{var vIIx3 = new Date();vIIx3[\"setUTCFullYear\"](\"2003\");if (vIIx3.getUTCFullYear().toString" ascii
    $s2 = "var vCYb5 = new Function(\"s\", '{var vIIx3 = new Date();vIIx3[\"setUTCFullYear\"](\"2003\");if (vIIx3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vGk6 = s.split(\"##\"); return vGk6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYe6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}