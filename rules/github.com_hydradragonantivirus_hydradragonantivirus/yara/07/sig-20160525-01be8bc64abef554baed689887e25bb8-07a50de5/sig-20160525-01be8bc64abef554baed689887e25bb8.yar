rule sig_20160525_01be8bc64abef554baed689887e25bb8 {
  meta:
    description = "datamaliciousorder - file 20160525_01be8bc64abef554baed689887e25bb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e295aabd82b2893d1bbfef948bfcfb926d3353ba8e84e89dbd4d063edc3904f0"

  strings:
    $s1 = "lock noitcnuf([tpircSW{ )e( hctac" fullword ascii
    $s2 = "fc nruter{)ecapsetihwxelfc(keppelc noitcnuf;};gedotdarc nruter{)gedotdarc(mc noitcnuf;};dnenoisillocc nruter{)dnenoisillocc(suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}