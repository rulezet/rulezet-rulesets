rule sig_20160525_eda557674035556c4bbfbc5ffabc872d {
  meta:
    description = "datamaliciousorder - file 20160525_eda557674035556c4bbfbc5ffabc872d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c587d98664a14947d4b53756091d735e359447ef7845d6b5054fa5a092a7aa6"

  strings:
    $s1 = "n\" = sdnetm rav;};imm nruter{)imm(rerednerm noitcnuf\\n;\"Te67x\\\\16x\\\\35x\\\\\" = eixodn rav\\n;\"iFf6x\\\\\" = gsmn rav\\n" ascii
    $s2 = " = ssorcaq rav\\n;\"07x\\\\s\" = rerednerq rav\\n;\"ic6x\\\\\" = imq rav\\n;\"e36x\\\\\" = eixodr rav\\n;\"t76x\\\\nel\" = gsmr " ascii
    $s3 = "PITQ\" = ecapsetihwxelfh rav;};imh nruter{)imh(rerednerh noitcnuf\\n;\"nec6x\\\\\" = eixodi rav\\n;\"t76x\\\\\" = gsmi rav\\n;\"" ascii
    $s4 = "f;};reredneri nruter{)reredneri(cthi noitcnuf;};tsilslianbmuhtoi nruter{)tsilslianbmuhtoi(ssorcai noitcnuf;};deerdi nruter{)deer" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}