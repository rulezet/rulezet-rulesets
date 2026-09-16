rule _20160921_87f13d652177c2ccba1196dd341efb6d_20160921_be882ab89423_5485 {
  meta:
    description = "datamaliciousorder - from files 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash2       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"

  strings:
    $s1 = "NBs\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(funct" ascii
    $s2 = "eturn \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s3 = "(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){re" ascii
    $s4 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(function f000" ascii
    $s5 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qj\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}