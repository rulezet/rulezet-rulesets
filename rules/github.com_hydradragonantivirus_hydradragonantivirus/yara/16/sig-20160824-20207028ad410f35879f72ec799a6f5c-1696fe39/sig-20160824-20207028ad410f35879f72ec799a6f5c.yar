rule sig_20160824_20207028ad410f35879f72ec799a6f5c {
  meta:
    description = "datamaliciousorder - file 20160824_20207028ad410f35879f72ec799a6f5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ef77fdb8583d1d45b07b9dd16d5bc1a467b65b367ac9efc0b1094608210b83"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}