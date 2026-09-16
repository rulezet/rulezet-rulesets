rule sig_20160525_84b2726c30871ada4042069e27903c6b {
  meta:
    description = "datamaliciousorder - file 20160525_84b2726c30871ada4042069e27903c6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8d41f0ed6d95a2af2c1aff6940e97862aa29b5677d167928dcf95a664f71c34"

  strings:
    $s1 = "lock noitcnuf([tpircSW{ )e( hctac" fullword ascii
    $s2 = "6x\\\\\"+\"\"+\"36x\\\\\"+\"\"[cthk = imk rav;\"mp1NYBp\" = cthk rav\\n;\"ta56x\\\\r34x\\\\\" = eixodl rav\\n;\"O56x\\\\\" = gsm" ascii
    $s3 = "fc nruter{)ecapsetihwxelfc(keppelc noitcnuf;};gedotdarc nruter{)gedotdarc(mc noitcnuf;};dnenoisillocc nruter{)dnenoisillocc(suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}