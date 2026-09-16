rule sig_20161206_56142e512c3238a92b101162835b6137 {
  meta:
    description = "datamaliciousorder - file 20161206_56142e512c3238a92b101162835b6137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fbfdad37fe4bfd3c0f3842726dad6e6a206470b753f06a4e89149066f8c4d3d"

  strings:
    $s1 = "var vXDj7 = new Function(\"s\", '{var vEGb3 = new Date();vEGb3[\"setUTCFullYear\"](\"2003\");if (vEGb3.getUTCFullYear().toString" ascii
    $s2 = "var vXDj7 = new Function(\"s\", '{var vEGb3 = new Date();vEGb3[\"setUTCFullYear\"](\"2003\");if (vEGb3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vBh1 = s.split(\"##\"); return vBh1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vLJv6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}