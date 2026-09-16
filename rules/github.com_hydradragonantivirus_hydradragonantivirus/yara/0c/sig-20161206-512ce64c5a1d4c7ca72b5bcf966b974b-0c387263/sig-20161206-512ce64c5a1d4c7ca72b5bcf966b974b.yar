rule sig_20161206_512ce64c5a1d4c7ca72b5bcf966b974b {
  meta:
    description = "datamaliciousorder - file 20161206_512ce64c5a1d4c7ca72b5bcf966b974b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e9966e5c28a8c58232489a1f79b8746cee8a26e5486179114e18dd73d26d86b"

  strings:
    $s1 = "var vRMp5 = new Function(\"s\", '{var vKWv9 = new Date();vKWv9[\"setUTCFullYear\"](\"2003\");if (vKWv9.getUTCFullYear().toString" ascii
    $s2 = "var vRMp5 = new Function(\"s\", '{var vKWv9 = new Date();vKWv9[\"setUTCFullYear\"](\"2003\");if (vKWv9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vWPo5 = s.split(\"##\"); return vWPo5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vDk9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}