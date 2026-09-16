rule sig_20161206_a8e3eb879c2c3ddefa7adf015d1b82bb {
  meta:
    description = "datamaliciousorder - file 20161206_a8e3eb879c2c3ddefa7adf015d1b82bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30991f49778e6d5371bfb5a2a7a4007af167d903ebb3699fe046f98db2aa8afc"

  strings:
    $s1 = "var vRf3 = new Function(\"s\", '{var vSt9 = new Date();vSt9[\"setUTCFullYear\"](\"2003\");if (vSt9.getUTCFullYear().toString(10)" ascii
    $s2 = "var vRf3 = new Function(\"s\", '{var vSt9 = new Date();vSt9[\"setUTCFullYear\"](\"2003\");if (vSt9.getUTCFullYear().toString(10)" ascii
    $s3 = "function vCWz1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vKw3 = s.split(\"##\"); return vKw3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}