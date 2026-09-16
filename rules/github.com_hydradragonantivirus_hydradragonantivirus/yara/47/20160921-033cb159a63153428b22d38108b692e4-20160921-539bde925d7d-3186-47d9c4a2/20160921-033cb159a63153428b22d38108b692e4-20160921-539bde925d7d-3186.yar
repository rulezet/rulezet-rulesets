rule _20160921_033cb159a63153428b22d38108b692e4_20160921_539bde925d7d_3186 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash4       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa" ascii
    $s2 = "\"Yv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s3 = "0(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\"" ascii
    $s4 = "function f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s5 = "on f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s6 = "on f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}