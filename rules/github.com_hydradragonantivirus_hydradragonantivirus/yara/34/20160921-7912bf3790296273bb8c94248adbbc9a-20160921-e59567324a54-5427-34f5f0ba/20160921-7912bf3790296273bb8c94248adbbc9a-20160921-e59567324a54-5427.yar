rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_e59567324a54_5427 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f0" ascii
    $s2 = "00(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl" ascii
    $s3 = ")(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f00" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(funct" ascii
    $s5 = "000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}