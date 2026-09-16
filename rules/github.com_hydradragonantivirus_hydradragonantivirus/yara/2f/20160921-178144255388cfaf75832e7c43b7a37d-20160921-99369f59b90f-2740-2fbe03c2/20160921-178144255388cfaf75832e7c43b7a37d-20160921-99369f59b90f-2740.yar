rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_99369f59b90f_2740 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash3       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash4       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "nction f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retu" ascii
    $s2 = "(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\"" ascii
    $s3 = "ion f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s4 = "on f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s5 = "HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s6 = "rn \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s7 = "eturn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RPt\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}