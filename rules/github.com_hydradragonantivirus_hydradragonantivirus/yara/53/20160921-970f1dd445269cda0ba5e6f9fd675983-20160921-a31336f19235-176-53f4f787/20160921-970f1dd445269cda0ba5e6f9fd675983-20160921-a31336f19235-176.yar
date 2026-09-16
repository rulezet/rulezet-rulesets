rule _20160921_970f1dd445269cda0ba5e6f9fd675983_20160921_a31336f19235_176 {
  meta:
    description = "datamaliciousorder - from files 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash2       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash3       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash4       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1  = "eturn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Tn\";})(),(" ascii
    $s2  = "n f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"" ascii
    $s3  = "n f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s4  = "function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s5  = "0(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MJq\"" ascii
    $s6  = "Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s7  = ")(),(function f000(){return \"KIc\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000" ascii
    $s8  = " f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br" ascii
    $s9  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s10 = "urn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})()," ascii
    $s11 = "unction f000(){return \"Vj\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Lo\";})(),(function f000(){retu" ascii
    $s12 = "){return \"Mt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s13 = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Y" ascii
    $s14 = "0(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";}" ascii
    $s15 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Qj\";}" ascii
    $s16 = "Mj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s17 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt" ascii
    $s18 = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MOc\";})(),(function f000(){return \"Vj\";})()" ascii
    $s19 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp" ascii
    $s20 = " f000(){return \"Yv\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Qa" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}