rule sig_20160824_ca287ecc01ef8437fcf12238c889a64d {
  meta:
    description = "datamaliciousorder - file 20160824_ca287ecc01ef8437fcf12238c889a64d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76a416e3bc84bf2b74ca9bb75aa80da8821f5acf4b58cd58fd30a85f620ee245"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}