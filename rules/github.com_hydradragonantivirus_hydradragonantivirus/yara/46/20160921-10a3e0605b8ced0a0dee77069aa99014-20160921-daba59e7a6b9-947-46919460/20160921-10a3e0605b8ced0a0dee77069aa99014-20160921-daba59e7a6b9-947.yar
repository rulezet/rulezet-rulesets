rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_daba59e7a6b9_947 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s2  = " f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s3  = "urn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mt\";})(),(f" ascii
    $s4  = "turn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})()," ascii
    $s5  = "n \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s6  = "000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br" ascii
    $s7  = "urn \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s8  = "){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qz\";})" ascii
    $s9  = "f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KX" ascii
    $s10 = "Gn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s11 = "})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s12 = "ction f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s13 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"EZu\";})(" ascii
    $s14 = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s15 = " \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s16 = "(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nx\";}" ascii
    $s17 = "0(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";" ascii
    $s18 = "function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s19 = "n \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s20 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZFe\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}