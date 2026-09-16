rule sig_20160525_65a8ba9dfd97dcec2689200c2302edc9 {
  meta:
    description = "datamaliciousorder - file 20160525_65a8ba9dfd97dcec2689200c2302edc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d5fe1d9df3c84850528883ae977ddfc39d6fe90014c2bcc8f91b7368f5104a"

  strings:
    $s1 = "7x\\\\\"+\"ahc\"[eixodt = dnenoisilloct rav;\"qhL\" = eixodt rav\\n;\"tgn56x\\\\l\" = mt rav\\n;\"86x\\\\\" = gedotdart rav'[\"s" ascii
    $s2 = "aph rav\\n;\"nec6x\\\\\" = mh rav\\n;\"h47x\\\\76x\\\\\" = gedotdarh rav;};tsilslianbmuhtoh nruter{)tsilslianbmuhtoh(ssorcah noi" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}