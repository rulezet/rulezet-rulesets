rule sig_20161206_652d951782bf0806bd52c440864895e0 {
  meta:
    description = "datamaliciousorder - file 20161206_652d951782bf0806bd52c440864895e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5e03c324da4a93bf1de6383771a9328664d941060f374bc8bd27ffc90d7ffb7"

  strings:
    $s1 = "var vWc5 = new Function(\"s\", '{var vMz8 = new Date();vMz8[\"setUTCFullYear\"](\"2003\");if (vMz8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vWc5 = new Function(\"s\", '{var vMz8 = new Date();vMz8[\"setUTCFullYear\"](\"2003\");if (vMz8.getUTCFullYear().toString(10)" ascii
    $s3 = "function vAAb4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vVb8 = s.split(\"##\"); return vVb8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}