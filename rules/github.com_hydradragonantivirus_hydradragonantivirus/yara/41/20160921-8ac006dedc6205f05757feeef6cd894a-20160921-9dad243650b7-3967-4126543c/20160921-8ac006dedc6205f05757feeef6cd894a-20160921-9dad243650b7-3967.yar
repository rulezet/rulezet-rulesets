rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_9dad243650b7_3967 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash3       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash4       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = "w\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s2 = "tion f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s3 = "(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s4 = "return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(" ascii
    $s5 = "n \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fun" ascii
    $s6 = "0(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}