rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_4d4f88bcbe1d_2733 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"

  strings:
    $s1 = "n f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii
    $s2 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000" ascii
    $s3 = "function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s4 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s5 = "(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s6 = "urn \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s7 = "(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}