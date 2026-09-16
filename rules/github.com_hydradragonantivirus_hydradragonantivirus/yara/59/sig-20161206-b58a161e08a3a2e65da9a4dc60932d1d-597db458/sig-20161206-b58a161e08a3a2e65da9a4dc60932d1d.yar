rule sig_20161206_b58a161e08a3a2e65da9a4dc60932d1d {
  meta:
    description = "datamaliciousorder - file 20161206_b58a161e08a3a2e65da9a4dc60932d1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b613e17fddd05b1f585a17da28c7f43e5ccfa3cc48609718f6ebc172eff82a9"

  strings:
    $s1 = "var vWh4 = new Function(\"s\", '{var vFl0 = new Date();vFl0[\"setUTCFullYear\"](\"2003\");if (vFl0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vWh4 = new Function(\"s\", '{var vFl0 = new Date();vFl0[\"setUTCFullYear\"](\"2003\");if (vFl0.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vJx4 = s.split(\"##\"); return vJx4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vWIs9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}