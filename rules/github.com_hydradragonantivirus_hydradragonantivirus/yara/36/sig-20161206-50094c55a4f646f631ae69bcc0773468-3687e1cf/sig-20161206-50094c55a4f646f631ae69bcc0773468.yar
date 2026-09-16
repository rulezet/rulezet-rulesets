rule sig_20161206_50094c55a4f646f631ae69bcc0773468 {
  meta:
    description = "datamaliciousorder - file 20161206_50094c55a4f646f631ae69bcc0773468.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbc0aa083a27efbde76214b9c4eb773005caa2d5d5c4dacc45a789edbffc1353"

  strings:
    $s1 = "var vOd1 = new Function(\"s\", '{var vADw1 = new Date();vADw1[\"setUTCFullYear\"](\"2003\");if (vADw1.getUTCFullYear().toString(" ascii
    $s2 = "var vOd1 = new Function(\"s\", '{var vADw1 = new Date();vADw1[\"setUTCFullYear\"](\"2003\");if (vADw1.getUTCFullYear().toString(" ascii
    $s3 = "function vOJb0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vVVs4 = s.split(\"##\"); return vVVs4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}