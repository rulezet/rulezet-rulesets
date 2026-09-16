rule _20160921_5ed9729c3ab2cb9d37d8a088af1aba59_20160921_65ff2a70ce98_5267 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash2       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash3       = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash4       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"
    hash5       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\"" ascii
    $s2 = " fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"L" ascii
    $s3 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s4 = "IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(functi" ascii
    $s5 = "ck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}