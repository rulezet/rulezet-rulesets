rule _20160921_6b34f0b83cb5d89ac574db511a389f02_20160921_95ced062e055_3875 {
  meta:
    description = "datamaliciousorder - from files 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_95ced062e0552048d29cf59daab852db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"

  strings:
    $s1 = "000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa" ascii
    $s2 = "0(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";" ascii
    $s3 = ")(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000" ascii
    $s4 = "urn \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s5 = "rn \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(" ascii
    $s6 = "ion f000(){return \"DIa\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}