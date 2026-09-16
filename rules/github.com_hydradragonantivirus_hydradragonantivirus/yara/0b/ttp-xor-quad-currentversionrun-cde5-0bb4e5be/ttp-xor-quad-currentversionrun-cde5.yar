rule TTP_XOR_QUAD_CurrentVersionRun_cde5 {
  strings:
    $key_cde5 = { 9e 8a [2] ba 84 [2] 91 a8 [2] bf 8a [2] ab 91 [2] a4 8b [2] ba 96 [2] b8 97 [2] a3 91 [2] bf 96 [2] a3 b9 }

  condition:
    any of them
}