rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160921_b86272ed73ce_215 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1  = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000" ascii
    $s2  = "Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s3  = "n f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s4  = "n f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"V" ascii
    $s5  = ",(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s6  = "urn \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s7  = "rn \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s8  = "\"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(funct" ascii
    $s9  = "){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";}" ascii
    $s10 = "00(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe" ascii
    $s11 = ",(function f000(){return \"Km\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){" ascii
    $s12 = "(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})" ascii
    $s13 = "\"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s14 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii
    $s15 = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(functio" ascii
    $s16 = ",(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){" ascii
    $s17 = "{return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})()" ascii
    $s18 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s19 = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(fun" ascii
    $s20 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}