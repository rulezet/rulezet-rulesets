rule sig_20160525_8906d45311e3a9e406279f7b844382a2 {
  meta:
    description = "datamaliciousorder - file 20160525_8906d45311e3a9e406279f7b844382a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "822b24cadc41e4793ae9a925b287fcfbac1a937c7ccc58a586a7e69af8c0c8f7"

  strings:
    $s1 = "lock noitcnuf([tpircSW{ )e( hctac" fullword ascii
    $s2 = "6x\\\\\"+\"\"+\"36x\\\\\"+\"\"[cthk = imk rav;\"mp1NYBp\" = cthk rav\\n;\"ta56x\\\\r34x\\\\\" = eixodl rav\\n;\"O56x\\\\\" = gsm" ascii
    $s3 = "fc nruter{)ecapsetihwxelfc(keppelc noitcnuf;};gedotdarc nruter{)gedotdarc(mc noitcnuf;};dnenoisillocc nruter{)dnenoisillocc(suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}