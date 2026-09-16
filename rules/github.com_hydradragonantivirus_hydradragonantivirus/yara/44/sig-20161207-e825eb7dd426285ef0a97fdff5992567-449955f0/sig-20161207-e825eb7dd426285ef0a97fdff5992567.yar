rule sig_20161207_e825eb7dd426285ef0a97fdff5992567 {
  meta:
    description = "datamaliciousorder - file 20161207_e825eb7dd426285ef0a97fdff5992567.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c923a03e81bfb6274c57bef9db505e992340e54bfb1b91ffc419ea21b62ae951"

  strings:
    $s1 = "var vAd0 = new Function(\"vEh9\", '{var vNMb3 = new Date();vNMb3[\"setUTCFullYear\"](\"2003\");if (vNMb3.getUTCFullYear().toStri" ascii
    $s2 = "var vAd0 = new Function(\"vEh9\", '{var vNMb3 = new Date();vNMb3[\"setUTCFullYear\"](\"2003\");if (vNMb3.getUTCFullYear().toStri" ascii
    $s3 = "var vSj3 = new Function(\"vEh9\", '{return vEh9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " == \"2003\") {var vQZx2 = vEh9.split(\"###\"); return vQZx2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}