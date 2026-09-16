rule TTP_XOR_QUAD_CurrentVersionRun_cdf5 {
  strings:
    $key_cdf5 = { 9e 9a [2] ba 94 [2] 91 b8 [2] bf 9a [2] ab 81 [2] a4 9b [2] ba 86 [2] b8 87 [2] a3 81 [2] bf 86 [2] a3 a9 }

  condition:
    any of them
}