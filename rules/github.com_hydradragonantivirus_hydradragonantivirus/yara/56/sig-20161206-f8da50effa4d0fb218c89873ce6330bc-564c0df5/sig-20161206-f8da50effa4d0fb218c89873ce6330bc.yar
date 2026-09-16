rule sig_20161206_f8da50effa4d0fb218c89873ce6330bc {
  meta:
    description = "datamaliciousorder - file 20161206_f8da50effa4d0fb218c89873ce6330bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d181bae027f82af369071b44632a8774a31d0436083e99ea8609f8c6d405fde"

  strings:
    $s1 = "var vAr7 = new Function(\"s\", '{var vUf9 = new Date();vUf9[\"setUTCFullYear\"](\"2003\");if (vUf9.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAr7 = new Function(\"s\", '{var vUf9 = new Date();vUf9[\"setUTCFullYear\"](\"2003\");if (vUf9.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vCWt6 = s.split(\"##\"); return vCWt6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vUZe3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}