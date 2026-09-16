rule sig_20161206_68c851eac9659c783888f0b7516221d1 {
  meta:
    description = "datamaliciousorder - file 20161206_68c851eac9659c783888f0b7516221d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71805a00e9a29bbbabf2abf339f4589c8987cd5d0ae22352b22c8aa685082feb"

  strings:
    $s1 = "var vRu1 = new Function(\"s\", '{var vUXe3 = new Date();vUXe3[\"setUTCFullYear\"](\"2003\");if (vUXe3.getUTCFullYear().toString(" ascii
    $s2 = "var vRu1 = new Function(\"s\", '{var vUXe3 = new Date();vUXe3[\"setUTCFullYear\"](\"2003\");if (vUXe3.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vOLy3 = s.split(\"##\"); return vOLy3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vKVc5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}