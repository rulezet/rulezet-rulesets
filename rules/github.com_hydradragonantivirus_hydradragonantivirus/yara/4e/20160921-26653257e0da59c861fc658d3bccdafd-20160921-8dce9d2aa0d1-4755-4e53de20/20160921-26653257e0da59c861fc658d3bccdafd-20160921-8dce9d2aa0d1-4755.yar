rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_8dce9d2aa0d1_4755 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_c694815b18c140f34c0f79f86106d901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash3       = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"

  strings:
    $s1 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s2 = ")(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s3 = " \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s4 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s5 = "fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IR" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}