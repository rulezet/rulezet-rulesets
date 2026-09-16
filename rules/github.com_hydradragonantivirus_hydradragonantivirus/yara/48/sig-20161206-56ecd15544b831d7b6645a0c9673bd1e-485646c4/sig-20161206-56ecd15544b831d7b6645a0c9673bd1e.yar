rule sig_20161206_56ecd15544b831d7b6645a0c9673bd1e {
  meta:
    description = "datamaliciousorder - file 20161206_56ecd15544b831d7b6645a0c9673bd1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8e369295eb035cbbe9fbce1f3046e03232e2e22542d596548415f22c569eaa7"

  strings:
    $s1 = "var vUx4 = new Function(\"s\", '{var vQf0 = new Date();vQf0[\"setUTCFullYear\"](\"2003\");if (vQf0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vUx4 = new Function(\"s\", '{var vQf0 = new Date();vQf0[\"setUTCFullYear\"](\"2003\");if (vQf0.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vYx3 = s.split(\"##\"); return vYx3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vAf2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}