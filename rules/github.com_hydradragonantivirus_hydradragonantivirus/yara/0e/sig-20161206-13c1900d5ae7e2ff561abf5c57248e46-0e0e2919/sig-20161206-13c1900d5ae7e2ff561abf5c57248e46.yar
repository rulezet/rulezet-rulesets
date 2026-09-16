rule sig_20161206_13c1900d5ae7e2ff561abf5c57248e46 {
  meta:
    description = "datamaliciousorder - file 20161206_13c1900d5ae7e2ff561abf5c57248e46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a24ea0b379e51b0eecd8d0947065446e697c962fd4ff412c6389a02ae6604c03"

  strings:
    $s1 = "var vOCd6 = new Function(\"s\", '{var vMl0 = new Date();vMl0[\"setUTCFullYear\"](\"2003\");if (vMl0.getUTCFullYear().toString(10" ascii
    $s2 = "var vOCd6 = new Function(\"s\", '{var vMl0 = new Date();vMl0[\"setUTCFullYear\"](\"2003\");if (vMl0.getUTCFullYear().toString(10" ascii
    $s3 = "function vTj3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vZOw8 = s.split(\"##\"); return vZOw8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}