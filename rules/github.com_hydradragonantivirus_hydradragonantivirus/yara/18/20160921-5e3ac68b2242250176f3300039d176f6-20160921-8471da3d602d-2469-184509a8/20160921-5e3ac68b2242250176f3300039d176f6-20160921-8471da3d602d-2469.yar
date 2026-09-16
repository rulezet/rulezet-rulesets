rule _20160921_5e3ac68b2242250176f3300039d176f6_20160921_8471da3d602d_2469 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = "y\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function " ascii
    $s2 = "rn \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(fu" ascii
    $s3 = "(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";" ascii
    $s4 = " \"Um\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s5 = "000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp" ascii
    $s6 = "\"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(funct" ascii
    $s7 = "f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do" ascii
    $s8 = "0(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}