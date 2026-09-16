rule _20160921_7ffe38e0972c323071684bfa98cafbdf_20160921_d7492227e681_556 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash2       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1  = "r\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function " ascii
    $s2  = "v\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3  = "urn \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s4  = "urn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s5  = "rn \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(" ascii
    $s6  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s7  = ",(function f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){" ascii
    $s8  = "Mz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s9  = "(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";" ascii
    $s10 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f" ascii
    $s11 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s12 = " \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(fun" ascii
    $s13 = "(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";" ascii
    $s14 = "rn \"EZu\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s15 = "on f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s16 = "ction f000(){return \"Lp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s17 = "){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"OMd\";})" ascii
    $s18 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s19 = "return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s20 = "return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}