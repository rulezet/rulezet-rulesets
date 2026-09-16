rule TTP_XOR_QUAD_CurrentVersionRun_cdd5 {
  strings:
    $key_cdd5 = { 9e ba [2] ba b4 [2] 91 98 [2] bf ba [2] ab a1 [2] a4 bb [2] ba a6 [2] b8 a7 [2] a3 a1 [2] bf a6 [2] a3 89 }

  condition:
    any of them
}