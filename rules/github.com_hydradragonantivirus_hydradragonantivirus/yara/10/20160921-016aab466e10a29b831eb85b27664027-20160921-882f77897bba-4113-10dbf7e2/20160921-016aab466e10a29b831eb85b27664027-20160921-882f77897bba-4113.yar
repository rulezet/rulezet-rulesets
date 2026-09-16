rule _20160921_016aab466e10a29b831eb85b27664027_20160921_882f77897bba_4113 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(funct" ascii
    $s2 = "ction f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s3 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){re" ascii
    $s4 = "000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu" ascii
    $s5 = "eturn \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}