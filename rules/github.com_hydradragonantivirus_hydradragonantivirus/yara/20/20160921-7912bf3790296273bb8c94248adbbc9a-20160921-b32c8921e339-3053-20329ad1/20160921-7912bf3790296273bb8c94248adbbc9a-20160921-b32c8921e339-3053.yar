rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_b32c8921e339_3053 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"PTs\";})" ascii
    $s2 = "){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})" ascii
    $s3 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s4 = "ction f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s5 = "000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn" ascii
    $s6 = "f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"PTs" ascii
    $s7 = "on f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}