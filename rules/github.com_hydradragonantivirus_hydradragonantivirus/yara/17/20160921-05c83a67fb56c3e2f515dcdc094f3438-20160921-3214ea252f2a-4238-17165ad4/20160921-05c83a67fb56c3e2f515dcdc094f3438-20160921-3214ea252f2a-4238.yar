rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_3214ea252f2a_4238 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"

  strings:
    $s1 = "{return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(" ascii
    $s2 = " fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"I" ascii
    $s3 = "b\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s4 = "function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s5 = "turn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}