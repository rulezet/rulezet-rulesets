rule _20160921_9d32b55f93b83e117524c4df15361eee_20160921_dd28b3b2e4fa_188 {
  meta:
    description = "datamaliciousorder - from files 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash2       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1  = ",(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){" ascii
    $s2  = "ion f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s3  = "rn \"SGs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s4  = "ion f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s5  = "000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";" ascii
    $s6  = "})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f00" ascii
    $s7  = "b\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function " ascii
    $s8  = "function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(),(function f000(){re" ascii
    $s9  = "(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){" ascii
    $s10 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s11 = " f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s12 = ")(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s13 = "return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})()," ascii
    $s14 = "on f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s15 = "on f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return " ascii
    $s16 = "\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mc\";})(),(function " ascii
    $s17 = "{return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Wb\";})()" ascii
    $s18 = "000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"DIa" ascii
    $s19 = "ZGq\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(functi" ascii
    $s20 = " \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}