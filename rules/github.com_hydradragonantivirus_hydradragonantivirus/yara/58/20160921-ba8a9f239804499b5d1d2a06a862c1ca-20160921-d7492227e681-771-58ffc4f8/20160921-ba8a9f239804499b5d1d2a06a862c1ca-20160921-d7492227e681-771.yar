rule _20160921_ba8a9f239804499b5d1d2a06a862c1ca_20160921_d7492227e681_771 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_d7492227e681b1689bfc5442a91a169e.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash2       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1  = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})()," ascii
    $s2  = "rn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Qa\";})(),(fun" ascii
    $s3  = "000(){return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx" ascii
    $s4  = "(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(" ascii
    $s5  = "rn \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s6  = "n f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return " ascii
    $s7  = "\"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DAp\";})(),(funct" ascii
    $s8  = "n f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MK" ascii
    $s9  = "unction f000(){return \"Ot\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){retur" ascii
    $s10 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";})(),(functi" ascii
    $s11 = "rn \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(f" ascii
    $s12 = "00(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vj\";" ascii
    $s13 = "\"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(funct" ascii
    $s14 = "unction f000(){return \"EZu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml\";})(),(function f000(){ret" ascii
    $s15 = "000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\"" ascii
    $s16 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(function f0" ascii
    $s17 = "c\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function" ascii
    $s18 = "nction f000(){return \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s19 = "nction f000(){return \"IAa\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s20 = "unction f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}