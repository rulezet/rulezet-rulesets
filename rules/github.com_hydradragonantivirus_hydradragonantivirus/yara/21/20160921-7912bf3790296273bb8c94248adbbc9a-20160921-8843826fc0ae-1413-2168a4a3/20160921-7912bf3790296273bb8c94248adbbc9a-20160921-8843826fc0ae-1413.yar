rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_8843826fc0ae_1413 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_8843826fc0ae466921b7811b54d8314e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"

  strings:
    $s1  = "tion f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2  = "f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s3  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f" ascii
    $s4  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Go\";})(),(function f000(" ascii
    $s5  = "nction f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return" ascii
    $s6  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";}" ascii
    $s7  = "0(){return \"IAa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";" ascii
    $s8  = "f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"NB" ascii
    $s9  = "ction f000(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s10 = " \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(fu" ascii
    $s11 = "urn \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s12 = "tion f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s13 = "rn \"Mt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s14 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}