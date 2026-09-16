rule TTP_XOR_QUAD_CurrentVersionRun_cdc9 {
  strings:
    $key_cdc9 = { 9e a6 [2] ba a8 [2] 91 84 [2] bf a6 [2] ab bd [2] a4 a7 [2] ba ba [2] b8 bb [2] a3 bd [2] bf ba [2] a3 95 }

  condition:
    any of them
}