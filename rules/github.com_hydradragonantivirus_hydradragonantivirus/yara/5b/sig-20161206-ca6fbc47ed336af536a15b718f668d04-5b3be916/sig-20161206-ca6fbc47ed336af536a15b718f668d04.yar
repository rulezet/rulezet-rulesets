rule sig_20161206_ca6fbc47ed336af536a15b718f668d04 {
  meta:
    description = "datamaliciousorder - file 20161206_ca6fbc47ed336af536a15b718f668d04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "251eb27315fa07d63cb0f209b2634794d4e792dd30f9a1de8dd170987a10f89d"

  strings:
    $s1 = "var vFj2 = new Function(\"s\", '{var vQEx5 = new Date();vQEx5[\"setUTCFullYear\"](\"2003\");if (vQEx5.getUTCFullYear().toString(" ascii
    $s2 = "var vFj2 = new Function(\"s\", '{var vQEx5 = new Date();vQEx5[\"setUTCFullYear\"](\"2003\");if (vQEx5.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vKDe2 = s.split(\"##\"); return vKDe2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYXf6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}