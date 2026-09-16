rule sig_20160824_7cd5d287b645a411acd908cadea09b26 {
  meta:
    description = "datamaliciousorder - file 20160824_7cd5d287b645a411acd908cadea09b26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffcd733ec197a8466d28ab416072c664b03b488665af71815283b9ccc7082c68"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}