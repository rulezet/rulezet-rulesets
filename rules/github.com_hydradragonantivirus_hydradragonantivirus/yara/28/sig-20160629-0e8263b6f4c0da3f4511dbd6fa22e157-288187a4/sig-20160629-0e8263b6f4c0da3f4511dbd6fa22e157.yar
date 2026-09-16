rule sig_20160629_0e8263b6f4c0da3f4511dbd6fa22e157 {
  meta:
    description = "datamaliciousorder - file 20160629_0e8263b6f4c0da3f4511dbd6fa22e157.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d24d730461d2cb946803905cc71843d93c2eae5631f78bd1e356a1e604dacf0"

  strings:
    $x1 = "var s12 = new Array();x10 = -595; x10 += 1246; s12[x10] = '.\"); '; x10 -= 1246;x10 = -7566; x10 += 7873; s12[x10] = 'le('; x10 " ascii
    $s2 = "; s12[x10] = 'l\"+cs+'; x10 -= 7421;x10 = -8691; x10 += 9100; s12[x10] = ' here'; x10 -= 9100;x10 = -5146; x10 += 6097; s12[x10]" ascii
    $s3 = "[x10] = ' soft'; x10 -= 903;x10 = -1003; x10 += 1450; s12[x10] = 'sh'; x10 -= 1450;x10 = -583; x10 += 1381; s12[x10] = 'mand'; x" ascii
    $s4 = "10 = -31; x10 += 639; s12[x10] = ' days '; x10 -= 639;x10 = -9156; x10 += 9270; s12[x10] = 'ect(\"A'; x10 -= 9270;x10 = -332; x1" ascii
    $s5 = "68; s12[x10] = ' rein'; x10 -= 4868;x10 = -6714; x10 += 6876; s12[x10] = '://'; x10 -= 6876;x10 = -2773; x10 += 2810; s12[x10] =" ascii
    $s6 = "10 += 7171; s12[x10] = 'n y'; x10 -= 7171;x10 = -9011; x10 += 9462; s12[x10] = 'h here'; x10 -= 9462;x10 = 98; x10 += 818; s12[x" ascii
    $s7 = "var s12 = new Array();x10 = -595; x10 += 1246; s12[x10] = '.\"); '; x10 -= 1246;x10 = -7566; x10 += 7873; s12[x10] = 'le('; x10 " ascii
    $s8 = "x10] = ' use'; x10 -= 2838;x10 = -7717; x10 += 8539; s12[x10] = ' copy'; x10 -= 8539;x10 = -5179; x10 += 5339; s12[x10] = '\",';" ascii
    $s9 = "173; s12[x10] = '+cq+'; x10 -= 7173;x10 = 102; x10 += 43; s12[x10] = 'for'; x10 -= 43;x10 = -276; x10 += 888; s12[x10] = ' YOUR'" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}