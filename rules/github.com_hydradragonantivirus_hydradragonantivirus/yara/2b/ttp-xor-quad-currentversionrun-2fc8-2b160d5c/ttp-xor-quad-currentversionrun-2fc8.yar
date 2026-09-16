rule TTP_XOR_QUAD_CurrentVersionRun_2fc8 {
  strings:
    $key_2fc8 = { 7c a7 [2] 58 a9 [2] 73 85 [2] 5d a7 [2] 49 bc [2] 46 a6 [2] 58 bb [2] 5a ba [2] 41 bc [2] 5d bb [2] 41 94 }

  condition:
    any of them
}