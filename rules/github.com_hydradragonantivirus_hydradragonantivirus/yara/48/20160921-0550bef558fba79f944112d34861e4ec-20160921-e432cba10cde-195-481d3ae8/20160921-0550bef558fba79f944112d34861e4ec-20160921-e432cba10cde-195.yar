rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_e432cba10cde_195 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1  = "n f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s2  = "})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000" ascii
    $s3  = "tion f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s4  = "urn \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s5  = "nction f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s6  = "unction f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s7  = "00(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\"" ascii
    $s8  = "unction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s9  = "{return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})" ascii
    $s10 = "urn \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s11 = "TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s12 = "w\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s13 = "urn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s14 = "ction f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s15 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s16 = "000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw" ascii
    $s17 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(" ascii
    $s18 = "{return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(" ascii
    $s19 = "urn \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(f" ascii
    $s20 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}