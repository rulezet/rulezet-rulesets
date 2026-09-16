rule sig_20161207_47c254c6c26a7d6250f7b443929d3f86 {
  meta:
    description = "datamaliciousorder - file 20161207_47c254c6c26a7d6250f7b443929d3f86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d910dcbcfabb01f5a980560cf1654e4a135bb49e95a92ea65dbf2776985713ab"

  strings:
    $s1 = "var vAh7 = new Function(\"vGVp1\", '{var vKx8 = new Date();vKx8[\"setUTCFullYear\"](\"2003\");if (vKx8.getUTCFullYear().toString" ascii
    $s2 = "var vAh7 = new Function(\"vGVp1\", '{var vKx8 = new Date();vKx8[\"setUTCFullYear\"](\"2003\");if (vKx8.getUTCFullYear().toString" ascii
    $s3 = "var vINs7 = new Function(\"vGVp1\", '{return vGVp1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vHKv6 = vGVp1.split(\"###\"); return vHKv6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}