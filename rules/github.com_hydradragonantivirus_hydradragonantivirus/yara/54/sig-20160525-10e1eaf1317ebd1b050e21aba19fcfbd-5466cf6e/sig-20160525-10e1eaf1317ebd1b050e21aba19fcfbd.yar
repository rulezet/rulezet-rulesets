rule sig_20160525_10e1eaf1317ebd1b050e21aba19fcfbd {
  meta:
    description = "datamaliciousorder - file 20160525_10e1eaf1317ebd1b050e21aba19fcfbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a518c880807e9e77322cdad03984c72f0a8ad71ae88e29d0cbc149920ee8f7"

  strings:
    $s1 = "napxE.dnenoisillocb = modnar rav\\n;)imh + )rerednerh(eixodi + cthh + tsilslianbmuhtoh(]ssorcag + )sdnetg(tsilslianbmuhtog + dee" ascii
    $s2 = "nete rav\\n;\"94e17x\\\\/\" = ssorcae rav;};cthe nruter{)cthe(tsilslianbmuhtoe noitcnuf\\n;\"0f6x\\\\6\" = rerednere rav\\n;\"a7" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}