rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160922_f0d656e55be0_1191 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1  = "tion f000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s2  = "{return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb\";})(" ascii
    $s3  = ")(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s4  = "turn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})()," ascii
    $s5  = "(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = ";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii
    $s7  = "(function f000(){return \"MBb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){r" ascii
    $s8  = "n \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(fun" ascii
    $s9  = "{return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})" ascii
    $s10 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s11 = "Eg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(functi" ascii
    $s12 = "n f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s13 = "\"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"RVb\";})(),(fun" ascii
    $s14 = "on f000(){return \"Tn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s15 = "})(),(function f000(){return \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"NBs\";})(),(function f0" ascii
    $s16 = "turn \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}