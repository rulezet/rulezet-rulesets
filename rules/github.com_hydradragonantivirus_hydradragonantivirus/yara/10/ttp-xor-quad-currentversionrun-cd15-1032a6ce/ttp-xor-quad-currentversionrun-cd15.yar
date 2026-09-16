rule TTP_XOR_QUAD_CurrentVersionRun_cd15 {
  strings:
    $key_cd15 = { 9e 7a [2] ba 74 [2] 91 58 [2] bf 7a [2] ab 61 [2] a4 7b [2] ba 66 [2] b8 67 [2] a3 61 [2] bf 66 [2] a3 49 }

  condition:
    any of them
}