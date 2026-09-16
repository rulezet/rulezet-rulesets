rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_994c4aa88136_4170 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"
    hash4       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "Eg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s2 = "nction f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){retur" ascii
    $s3 = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f" ascii
    $s4 = "000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe" ascii
    $s5 = "function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}