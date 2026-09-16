rule _20160921_8d22ed47876b303a1415a88483556238_20160921_e927a1d46f63_2536 {
  meta:
    description = "datamaliciousorder - from files 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash2       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = "(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"UEg\"" ascii
    $s3 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){retu" ascii
    $s4 = "ion f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return " ascii
    $s5 = "unction f000(){return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Wh\";})(),(function f000(){retu" ascii
    $s6 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Yx\";})(),(function " ascii
    $s7 = "turn \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s8 = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}