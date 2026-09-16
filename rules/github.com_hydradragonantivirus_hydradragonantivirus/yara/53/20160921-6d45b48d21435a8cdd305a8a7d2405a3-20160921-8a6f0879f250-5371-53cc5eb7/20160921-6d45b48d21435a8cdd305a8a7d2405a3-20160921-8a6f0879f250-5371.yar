rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_8a6f0879f250_5371 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash5       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "urn \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s2 = "ion f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s3 = "j\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s4 = "tion f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5 = "Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Yz\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}