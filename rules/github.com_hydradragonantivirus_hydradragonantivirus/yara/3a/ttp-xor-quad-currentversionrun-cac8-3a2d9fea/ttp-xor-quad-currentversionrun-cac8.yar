rule TTP_XOR_QUAD_CurrentVersionRun_cac8 {
  strings:
    $key_cac8 = { 99 a7 [2] bd a9 [2] 96 85 [2] b8 a7 [2] ac bc [2] a3 a6 [2] bd bb [2] bf ba [2] a4 bc [2] b8 bb [2] a4 94 }

  condition:
    any of them
}