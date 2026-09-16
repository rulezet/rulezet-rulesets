rule sig_20161206_0569eae1754caa575f9b265374b3b44b {
  meta:
    description = "datamaliciousorder - file 20161206_0569eae1754caa575f9b265374b3b44b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfc6000d31c020c0e1be06c30f8349df99b4117ff876d39de1a3ea13934165e9"

  strings:
    $s1 = "var vWUt2 = new Function(\"s\", '{var vNy1 = new Date();vNy1[\"setUTCFullYear\"](\"2003\");if (vNy1.getUTCFullYear().toString(10" ascii
    $s2 = "var vWUt2 = new Function(\"s\", '{var vNy1 = new Date();vNy1[\"setUTCFullYear\"](\"2003\");if (vNy1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vYSb3 = s.split(\"##\"); return vYSb3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vWh9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}