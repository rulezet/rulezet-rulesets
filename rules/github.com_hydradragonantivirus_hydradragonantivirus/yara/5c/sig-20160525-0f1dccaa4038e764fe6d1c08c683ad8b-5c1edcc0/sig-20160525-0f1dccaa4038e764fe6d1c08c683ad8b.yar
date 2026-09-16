rule sig_20160525_0f1dccaa4038e764fe6d1c08c683ad8b {
  meta:
    description = "datamaliciousorder - file 20160525_0f1dccaa4038e764fe6d1c08c683ad8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07009b5e3d4aa658c8fcc4b369b9dc47dfe56766239ca45d6da0c9abbdab9343"

  strings:
    $s1 = "6x\\\\\" = img rav\\n;\"47x\\\\\" = eixodh rav;};tsilslianbmuhtoh nruter{)tsilslianbmuhtoh(ssorcah noitcnuf;};sdneth nruter{)sdn" ascii
    $s2 = "cthk rav;};ml nruter{)ml(dnenoisillocl noitcnuf;};gsml nruter{)gsml(eixodl noitcnuf\\n;\"E74x\\\\\" = ecapsetihwxelfl rav\\n;)3(" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}