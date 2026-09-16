rule TTP_XOR_QUAD_CurrentVersionRun_cd04 {
  strings:
    $key_cd04 = { 9e 6b [2] ba 65 [2] 91 49 [2] bf 6b [2] ab 70 [2] a4 6a [2] ba 77 [2] b8 76 [2] a3 70 [2] bf 77 [2] a3 58 }

  condition:
    any of them
}