rule TTP_XOR_QUAD_CurrentVersionRun_66c8 {
  strings:
    $key_66c8 = { 35 a7 [2] 11 a9 [2] 3a 85 [2] 14 a7 [2] 00 bc [2] 0f a6 [2] 11 bb [2] 13 ba [2] 08 bc [2] 14 bb [2] 08 94 }

  condition:
    any of them
}