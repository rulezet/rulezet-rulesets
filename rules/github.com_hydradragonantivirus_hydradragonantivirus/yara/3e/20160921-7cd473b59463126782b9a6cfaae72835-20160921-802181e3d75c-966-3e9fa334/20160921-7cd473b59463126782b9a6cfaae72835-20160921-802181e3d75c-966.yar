rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_802181e3d75c_966 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1  = "0(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl" ascii
    $s2  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){retu" ascii
    $s3  = "XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s4  = "ction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";})(),(function f000(){retur" ascii
    $s5  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Km\";})(),(function f000(){return " ascii
    $s6  = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function " ascii
    $s7  = "turn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})()" ascii
    $s8  = "f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WI" ascii
    $s9  = "urn \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(f" ascii
    $s10 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(funct" ascii
    $s11 = "Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s12 = "on f000(){return \"Vj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"" ascii
    $s13 = "00(){return \"EZu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s14 = " \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(func" ascii
    $s15 = "nction f000(){return \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s16 = ";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s17 = ",(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s18 = "(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s19 = "n\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function " ascii
    $s20 = "0(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}