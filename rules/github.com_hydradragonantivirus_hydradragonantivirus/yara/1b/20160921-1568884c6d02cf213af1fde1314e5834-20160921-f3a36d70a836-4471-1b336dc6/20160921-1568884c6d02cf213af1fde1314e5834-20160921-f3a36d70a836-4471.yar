rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_f3a36d70a836_4471 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(" ascii
    $s2 = "function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s3 = "unction f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s4 = " f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s5 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}