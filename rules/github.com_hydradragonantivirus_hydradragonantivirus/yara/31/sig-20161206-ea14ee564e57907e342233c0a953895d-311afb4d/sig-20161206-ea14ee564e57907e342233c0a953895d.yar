rule sig_20161206_ea14ee564e57907e342233c0a953895d {
  meta:
    description = "datamaliciousorder - file 20161206_ea14ee564e57907e342233c0a953895d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2f2fc5f246ffcbf71a4e9deba2344487bb6b9927d1e6df4249c5adbc1c89419"

  strings:
    $s1 = "var vQu1 = new Function(\"s\", '{var vXPu1 = new Date();vXPu1[\"setUTCFullYear\"](\"2003\");if (vXPu1.getUTCFullYear().toString(" ascii
    $s2 = "var vQu1 = new Function(\"s\", '{var vXPu1 = new Date();vXPu1[\"setUTCFullYear\"](\"2003\");if (vXPu1.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vMTl9 = s.split(\"##\"); return vMTl9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vMa8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}