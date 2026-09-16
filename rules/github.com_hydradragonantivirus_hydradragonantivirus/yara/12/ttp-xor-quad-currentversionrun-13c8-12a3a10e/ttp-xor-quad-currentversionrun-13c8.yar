rule TTP_XOR_QUAD_CurrentVersionRun_13c8 {
  strings:
    $key_13c8 = { 40 a7 [2] 64 a9 [2] 4f 85 [2] 61 a7 [2] 75 bc [2] 7a a6 [2] 64 bb [2] 66 ba [2] 7d bc [2] 61 bb [2] 7d 94 }

  condition:
    any of them
}