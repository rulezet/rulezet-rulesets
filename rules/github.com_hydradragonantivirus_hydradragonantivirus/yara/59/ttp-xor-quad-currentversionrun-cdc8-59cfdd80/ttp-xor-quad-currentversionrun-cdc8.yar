rule TTP_XOR_QUAD_CurrentVersionRun_cdc8 {
  strings:
    $key_cdc8 = { 9e a7 [2] ba a9 [2] 91 85 [2] bf a7 [2] ab bc [2] a4 a6 [2] ba bb [2] b8 ba [2] a3 bc [2] bf bb [2] a3 94 }

  condition:
    any of them
}