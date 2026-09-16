rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_5d76de82063e_4856 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash3       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1 = "000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s2 = "n \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s3 = " \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(fu" ascii
    $s4 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000()" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}