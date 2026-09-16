rule sig_20161206_0957ee03dfe404c1da1aaaca49a444ba {
  meta:
    description = "datamaliciousorder - file 20161206_0957ee03dfe404c1da1aaaca49a444ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69bc4af936ba7d9744bc1890559dab46e5781e3ef4778c3fc898536cca1c07f0"

  strings:
    $s1 = "var vEb9 = new Function(\"s\", '{var vWq6 = new Date();vWq6[\"setUTCFullYear\"](\"2003\");if (vWq6.getUTCFullYear().toString(10)" ascii
    $s2 = "var vEb9 = new Function(\"s\", '{var vWq6 = new Date();vWq6[\"setUTCFullYear\"](\"2003\");if (vWq6.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vMu0 = s.split(\"##\"); return vMu0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vJKu8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}