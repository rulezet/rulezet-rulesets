rule sig_20161206_87033d4d2ef0b0da12f978aafc2a2148 {
  meta:
    description = "datamaliciousorder - file 20161206_87033d4d2ef0b0da12f978aafc2a2148.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4225a1b04f0084fdd487ead5b541d9f6d2e805686e59347d1ad093029f4cc64d"

  strings:
    $s1 = "var vDZr6 = new Function(\"s\", '{var vRi2 = new Date();vRi2[\"setUTCFullYear\"](\"2003\");if (vRi2.getUTCFullYear().toString(10" ascii
    $s2 = "var vDZr6 = new Function(\"s\", '{var vRi2 = new Date();vRi2[\"setUTCFullYear\"](\"2003\");if (vRi2.getUTCFullYear().toString(10" ascii
    $s3 = "function vWDy4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vJJm9 = s.split(\"##\"); return vJJm9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}