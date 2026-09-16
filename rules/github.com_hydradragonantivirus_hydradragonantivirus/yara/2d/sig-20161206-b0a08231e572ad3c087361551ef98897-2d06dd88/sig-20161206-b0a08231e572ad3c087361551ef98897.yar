rule sig_20161206_b0a08231e572ad3c087361551ef98897 {
  meta:
    description = "datamaliciousorder - file 20161206_b0a08231e572ad3c087361551ef98897.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11619bbc3e8b00af18ff8613da3ad0589172344cd232b32442f3032d8f6df125"

  strings:
    $s1 = "var vNc0 = new Function(\"s\", '{var vCGa6 = new Date();vCGa6[\"setUTCFullYear\"](\"2003\");if (vCGa6.getUTCFullYear().toString(" ascii
    $s2 = "var vNc0 = new Function(\"s\", '{var vCGa6 = new Date();vCGa6[\"setUTCFullYear\"](\"2003\");if (vCGa6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vIf3 = s.split(\"##\"); return vIf3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vTa9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}