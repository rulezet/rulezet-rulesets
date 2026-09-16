rule sig_20161206_de6577995c73646db6d17658c09364a0 {
  meta:
    description = "datamaliciousorder - file 20161206_de6577995c73646db6d17658c09364a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5f5e4666c53145263e0aa773cf301ef6eef1fe9ca166aa02cb87a396821be50"

  strings:
    $s1 = "var vLXq7 = new Function(\"s\", '{var vFt5 = new Date();vFt5[\"setUTCFullYear\"](\"2003\");if (vFt5.getUTCFullYear().toString(10" ascii
    $s2 = "var vLXq7 = new Function(\"s\", '{var vFt5 = new Date();vFt5[\"setUTCFullYear\"](\"2003\");if (vFt5.getUTCFullYear().toString(10" ascii
    $s3 = "function vSCx4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vXBe4 = s.split(\"##\"); return vXBe4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}