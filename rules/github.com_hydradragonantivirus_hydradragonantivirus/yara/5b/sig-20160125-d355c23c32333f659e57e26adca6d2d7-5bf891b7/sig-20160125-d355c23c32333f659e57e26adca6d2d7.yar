rule sig_20160125_d355c23c32333f659e57e26adca6d2d7 {
  meta:
    description = "datamaliciousorder - file 20160125_d355c23c32333f659e57e26adca6d2d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af7e19b2e44aef54be23fa0f94d76d6dfb1cea76e909b13e8f14258ff58ffc2f"

  strings:
    $s1 = "var vocrnu='fkdsluatjyngquxcchbfteynpidomqofwatnmjeq qwbwdbkuqlwpnh(nonzfpaprrybht,rimd orteffuaenjuug,whog cbfjrvuarnqiku)oxxi{" ascii
    $s2 = ";fivt fxcv ynzd sncr wyke tyhu nzlkxwnfuaybnb.dpwdsjwhcajktcvcegfenoavTzmgbomlvvFyiwliptpclhweyecybq(whvffivbknshlh,pgcf szqo2cf" ascii
    $s3 = ".length){    a2 +=a1.charAt(a);a +=a3;   };     this[dm](a2);        //1EJzxMttAz" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}