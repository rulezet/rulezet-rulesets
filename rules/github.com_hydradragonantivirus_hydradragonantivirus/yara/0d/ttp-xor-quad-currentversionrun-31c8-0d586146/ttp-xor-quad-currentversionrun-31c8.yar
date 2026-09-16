rule TTP_XOR_QUAD_CurrentVersionRun_31c8 {
  strings:
    $key_31c8 = { 62 a7 [2] 46 a9 [2] 6d 85 [2] 43 a7 [2] 57 bc [2] 58 a6 [2] 46 bb [2] 44 ba [2] 5f bc [2] 43 bb [2] 5f 94 }

  condition:
    any of them
}