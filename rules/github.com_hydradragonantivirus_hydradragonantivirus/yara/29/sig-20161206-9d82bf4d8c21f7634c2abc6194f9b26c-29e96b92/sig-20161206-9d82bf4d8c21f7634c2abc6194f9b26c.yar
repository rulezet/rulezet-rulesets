rule sig_20161206_9d82bf4d8c21f7634c2abc6194f9b26c {
  meta:
    description = "datamaliciousorder - file 20161206_9d82bf4d8c21f7634c2abc6194f9b26c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eaa0be7d01a2881d01ed06df3dc7d24e0b7385e5422721d0dbffb994857cbe2"

  strings:
    $s1 = "var vHr3 = new Function(\"s\", '{var vBs2 = new Date();vBs2[\"setUTCFullYear\"](\"2003\");if (vBs2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vHr3 = new Function(\"s\", '{var vBs2 = new Date();vBs2[\"setUTCFullYear\"](\"2003\");if (vBs2.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vTb8 = s.split(\"##\"); return vTb8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vXz8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}