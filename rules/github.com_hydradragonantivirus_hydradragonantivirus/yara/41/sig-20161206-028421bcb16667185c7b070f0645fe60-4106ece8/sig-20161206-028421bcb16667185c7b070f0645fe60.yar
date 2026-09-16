rule sig_20161206_028421bcb16667185c7b070f0645fe60 {
  meta:
    description = "datamaliciousorder - file 20161206_028421bcb16667185c7b070f0645fe60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b0e8e931d59f4ef7e5bcd1200757dcdf2321c80304d19dc3849aeb2a1382e41"

  strings:
    $s1 = "var vITm1 = new Function(\"s\", '{var vIVt1 = new Date();vIVt1[\"setUTCFullYear\"](\"2003\");if (vIVt1.getUTCFullYear().toString" ascii
    $s2 = "var vITm1 = new Function(\"s\", '{var vIVt1 = new Date();vIVt1[\"setUTCFullYear\"](\"2003\");if (vIVt1.getUTCFullYear().toString" ascii
    $s3 = "function vRYd0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vXAw5 = s.split(\"##\"); return vXAw5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}