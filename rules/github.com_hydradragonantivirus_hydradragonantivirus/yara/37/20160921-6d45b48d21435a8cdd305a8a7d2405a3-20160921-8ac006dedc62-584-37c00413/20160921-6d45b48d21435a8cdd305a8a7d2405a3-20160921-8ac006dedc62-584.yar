rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_8ac006dedc62_584 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1  = "tion f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2  = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){ret" ascii
    $s3  = "v\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s4  = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NYh\";})(),(funct" ascii
    $s5  = "unction f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s6  = "{return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})" ascii
    $s7  = " \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(fun" ascii
    $s8  = "Gs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s9  = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f0" ascii
    $s10 = " \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(fun" ascii
    $s11 = "ion f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s12 = "eturn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MJq\";})()" ascii
    $s13 = "nction f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){ret" ascii
    $s14 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(f" ascii
    $s15 = "Db\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function " ascii
    $s16 = "rn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(f" ascii
    $s17 = "(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";" ascii
    $s18 = "(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000()" ascii
    $s19 = "on f000(){return \"UEg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s20 = "function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}