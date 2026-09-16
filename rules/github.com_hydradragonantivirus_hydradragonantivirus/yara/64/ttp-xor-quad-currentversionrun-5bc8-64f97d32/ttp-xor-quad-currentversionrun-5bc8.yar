rule TTP_XOR_QUAD_CurrentVersionRun_5bc8 {
  strings:
    $key_5bc8 = { 08 a7 [2] 2c a9 [2] 07 85 [2] 29 a7 [2] 3d bc [2] 32 a6 [2] 2c bb [2] 2e ba [2] 35 bc [2] 29 bb [2] 35 94 }

  condition:
    any of them
}