rule _20160921_02b826231ece268e91633311d2c70554_20160921_46b3ab412369_775 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash3       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash4       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash5       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash6       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s2  = "})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s3  = "urn \"PTi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s4  = "eturn \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})()," ascii
    $s5  = "n f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s6  = ",(function f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){re" ascii
    $s7  = "ion f000(){return \"YTp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s8  = " f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"B" ascii
    $s9  = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km" ascii
    $s10 = "n f000(){return \"Br\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"R" ascii
    $s11 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Br\";})" ascii
    $s12 = "\"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s13 = "tion f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return" ascii
    $s14 = "n \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s15 = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tb\";})(),(function f000(){ret" ascii
    $s16 = "f000(){return \"PTi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br" ascii
    $s17 = "urn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(fu" ascii
    $s18 = "(){return \"SEo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\"" ascii
    $s19 = "n \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(func" ascii
    $s20 = "0(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}