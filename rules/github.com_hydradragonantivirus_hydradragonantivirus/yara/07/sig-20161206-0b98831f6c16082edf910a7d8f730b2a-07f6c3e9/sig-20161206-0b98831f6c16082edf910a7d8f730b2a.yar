rule sig_20161206_0b98831f6c16082edf910a7d8f730b2a {
  meta:
    description = "datamaliciousorder - file 20161206_0b98831f6c16082edf910a7d8f730b2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c69fb18d26487ff2a408eb1b34825440a2166de84c9a478ca3be56ee802ac3ca"

  strings:
    $s1 = "var vKk2 = new Function(\"s\", '{var vKx1 = new Date();vKx1[\"setUTCFullYear\"](\"2003\");if (vKx1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vKk2 = new Function(\"s\", '{var vKx1 = new Date();vKx1[\"setUTCFullYear\"](\"2003\");if (vKx1.getUTCFullYear().toString(10)" ascii
    $s3 = "function vNWy4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vDz3 = s.split(\"##\"); return vDz3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}