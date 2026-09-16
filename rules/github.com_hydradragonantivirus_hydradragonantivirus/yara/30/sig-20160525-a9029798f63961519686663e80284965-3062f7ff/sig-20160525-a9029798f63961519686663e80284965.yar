rule sig_20160525_a9029798f63961519686663e80284965 {
  meta:
    description = "datamaliciousorder - file 20160525_a9029798f63961519686663e80284965.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca28ba0698ee1b8517527eb2e2445ae291a467f389ad64b118896d1c18879378"

  strings:
    $s1 = "7x\\\\\"+\"ahc\"[eixodt = dnenoisilloct rav;\"qhL\" = eixodt rav\\n;\"tgn56x\\\\l\" = mt rav\\n;\"86x\\\\\" = gedotdart rav'[\"s" ascii
    $s2 = "aph rav\\n;\"nec6x\\\\\" = mh rav\\n;\"h47x\\\\76x\\\\\" = gedotdarh rav;};tsilslianbmuhtoh nruter{)tsilslianbmuhtoh(ssorcah noi" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}