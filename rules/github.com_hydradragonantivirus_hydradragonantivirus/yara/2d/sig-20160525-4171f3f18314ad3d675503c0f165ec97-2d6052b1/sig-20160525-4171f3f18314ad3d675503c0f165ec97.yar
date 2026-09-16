rule sig_20160525_4171f3f18314ad3d675503c0f165ec97 {
  meta:
    description = "datamaliciousorder - file 20160525_4171f3f18314ad3d675503c0f165ec97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b774f51b7542022ff78d31d858d28a816d465dad4f9984f6d3c439dc186143"

  strings:
    $s1 = "loci + suidarelcitrapi + gsmi + ))(};eixodi nruter{)(modnari noitcnuf([ = ssorca rav\\n\\n;rerednerh + )ssorcah(tsilslianbmuhtoh" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}