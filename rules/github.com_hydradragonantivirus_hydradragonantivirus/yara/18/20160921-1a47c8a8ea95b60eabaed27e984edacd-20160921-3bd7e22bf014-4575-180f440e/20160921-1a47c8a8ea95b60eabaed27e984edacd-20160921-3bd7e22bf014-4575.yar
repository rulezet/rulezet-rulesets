rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_3bd7e22bf014_4575 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash3       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash4       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash5       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"

  strings:
    $s1 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii
    $s2 = "{return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s3 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s4 = " \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s5 = " fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}