rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_5d76de82063e_4619 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"

  strings:
    $s1 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mc\";})(),(funct" ascii
    $s2 = "on f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s3 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BMj\";})" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\";})(),(funct" ascii
    $s5 = "),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}