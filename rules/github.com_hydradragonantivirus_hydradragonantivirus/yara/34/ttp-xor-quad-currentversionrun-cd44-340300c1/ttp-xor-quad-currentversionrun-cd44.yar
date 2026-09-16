rule TTP_XOR_QUAD_CurrentVersionRun_cd44 {
  strings:
    $key_cd44 = { 9e 2b [2] ba 25 [2] 91 09 [2] bf 2b [2] ab 30 [2] a4 2a [2] ba 37 [2] b8 36 [2] a3 30 [2] bf 37 [2] a3 18 }

  condition:
    any of them
}