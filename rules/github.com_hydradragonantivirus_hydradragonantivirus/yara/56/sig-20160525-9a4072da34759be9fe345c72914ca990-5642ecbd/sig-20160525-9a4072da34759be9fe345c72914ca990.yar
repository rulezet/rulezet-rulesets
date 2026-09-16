rule sig_20160525_9a4072da34759be9fe345c72914ca990 {
  meta:
    description = "datamaliciousorder - file 20160525_9a4072da34759be9fe345c72914ca990.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4668d09b24d6e47716991f70d90ff40c8e8ff76c10b0c1ec85869f0f539237de"

  strings:
    $s1 = "dari + mi + dnenoisilloci + suidarelcitrapi ,imh + )rerednerh(eixodi + cthh + tsilslianbmuhtoh + ssorcah + sdneth + deerdh + mod" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}