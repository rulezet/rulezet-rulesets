rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_18f3e0383dae_4473 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"

  strings:
    $s1 = ",(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){" ascii
    $s2 = "n f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"" ascii
    $s3 = "ion f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";" ascii
    $s5 = "nction f000(){return \"Mc\";})(),(function f000(){return \"Yx\";})(),(function f000(){return \"Wh\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}