rule sig_20161206_eeea420eb25047e43420cda20c83ba85 {
  meta:
    description = "datamaliciousorder - file 20161206_eeea420eb25047e43420cda20c83ba85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c36f861cc12c5f85937da04e70aaf882fcfc1ff75f58d24b24f8bcb97902e4f6"

  strings:
    $s1 = "var vQe0 = new Function(\"s\", '{var vDk7 = new Date();vDk7[\"setUTCFullYear\"](\"2003\");if (vDk7.getUTCFullYear().toString(10)" ascii
    $s2 = "var vQe0 = new Function(\"s\", '{var vDk7 = new Date();vDk7[\"setUTCFullYear\"](\"2003\");if (vDk7.getUTCFullYear().toString(10)" ascii
    $s3 = "function vQIm9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vAXc5 = s.split(\"##\"); return vAXc5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}