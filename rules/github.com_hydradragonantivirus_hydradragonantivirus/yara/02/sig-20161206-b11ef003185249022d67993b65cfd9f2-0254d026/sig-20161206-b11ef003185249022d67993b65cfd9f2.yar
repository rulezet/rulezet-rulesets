rule sig_20161206_b11ef003185249022d67993b65cfd9f2 {
  meta:
    description = "datamaliciousorder - file 20161206_b11ef003185249022d67993b65cfd9f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31573849026a56050489a7496a8725d0ad1f9ee05abd5c4648103477b43554ba"

  strings:
    $s1 = "var vELy2 = new Function(\"s\", '{var vVj0 = new Date();vVj0[\"setUTCFullYear\"](\"2003\");if (vVj0.getUTCFullYear().toString(10" ascii
    $s2 = "var vELy2 = new Function(\"s\", '{var vVj0 = new Date();vVj0[\"setUTCFullYear\"](\"2003\");if (vVj0.getUTCFullYear().toString(10" ascii
    $s3 = "function vVa1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vGg5 = s.split(\"##\"); return vGg5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}