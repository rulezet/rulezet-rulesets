rule sig_20161206_b9b5a50d686b2e879497c519715af277 {
  meta:
    description = "datamaliciousorder - file 20161206_b9b5a50d686b2e879497c519715af277.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e854073d7f2531fde8b71b362f36c44b43759009c549123f995a0a5d4d204fd"

  strings:
    $s1 = "var vDGc0 = new Function(\"s\", '{var vUj5 = new Date();vUj5[\"setUTCFullYear\"](\"2003\");if (vUj5.getUTCFullYear().toString(10" ascii
    $s2 = "var vDGc0 = new Function(\"s\", '{var vUj5 = new Date();vUj5[\"setUTCFullYear\"](\"2003\");if (vUj5.getUTCFullYear().toString(10" ascii
    $s3 = "function vLSc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vPHt8 = s.split(\"##\"); return vPHt8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}