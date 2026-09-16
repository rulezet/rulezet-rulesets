rule _20160921_2eacd3ef1ce6866325342ce8cba80e38_20160921_8471da3d602d_2340 {
  meta:
    description = "datamaliciousorder - from files 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = "n f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"V" ascii
    $s2 = "nction f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s3 = "turn \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})()," ascii
    $s4 = "MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s5 = "(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";" ascii
    $s6 = "00(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\"" ascii
    $s7 = ",(function f000(){return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){" ascii
    $s8 = ";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}