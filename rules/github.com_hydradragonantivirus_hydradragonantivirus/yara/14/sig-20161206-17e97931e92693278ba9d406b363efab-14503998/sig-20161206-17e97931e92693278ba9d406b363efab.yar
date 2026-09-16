rule sig_20161206_17e97931e92693278ba9d406b363efab {
  meta:
    description = "datamaliciousorder - file 20161206_17e97931e92693278ba9d406b363efab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37479bc1589d89d9dddb64d3ba3aeaf5d2bd60a59598299a63098cf225ab94ef"

  strings:
    $s1 = "var vOo4 = new Function(\"s\", '{var vJRg0 = new Date();vJRg0[\"setUTCFullYear\"](\"2003\");if (vJRg0.getUTCFullYear().toString(" ascii
    $s2 = "var vOo4 = new Function(\"s\", '{var vJRg0 = new Date();vJRg0[\"setUTCFullYear\"](\"2003\");if (vJRg0.getUTCFullYear().toString(" ascii
    $s3 = "function vVJn2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vXKx1 = s.split(\"##\"); return vXKx1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}