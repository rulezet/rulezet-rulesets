rule _20160921_63def3fff7f150b1f60fee716b458fd6_20160921_b2002e7f99c6_506 {
  meta:
    description = "datamaliciousorder - from files 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1  = "\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f" ascii
    $s2  = "000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s3  = "n \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s4  = ",(function f000(){return \"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){r" ascii
    $s5  = "QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(functio" ascii
    $s6  = "000(){return \"ZGq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do" ascii
    $s7  = "00(){return \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\"" ascii
    $s8  = "function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s9  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s10 = " \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s11 = ")(),(function f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s12 = "n f000(){return \"Lp\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s13 = " f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"S" ascii
    $s14 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MBb\";})()," ascii
    $s15 = "unction f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s16 = "eturn \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTs\";})()" ascii
    $s17 = "000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TK" ascii
    $s18 = "return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s19 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){r" ascii
    $s20 = "Yh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}