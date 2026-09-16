rule TTP_XOR_QUAD_CurrentVersionRun_1bc8 {
  strings:
    $key_1bc8 = { 48 a7 [2] 6c a9 [2] 47 85 [2] 69 a7 [2] 7d bc [2] 72 a6 [2] 6c bb [2] 6e ba [2] 75 bc [2] 69 bb [2] 75 94 }

  condition:
    any of them
}