rule TTP_XOR_QUAD_CurrentVersionRun_2ec8 {
  strings:
    $key_2ec8 = { 7d a7 [2] 59 a9 [2] 72 85 [2] 5c a7 [2] 48 bc [2] 47 a6 [2] 59 bb [2] 5b ba [2] 40 bc [2] 5c bb [2] 40 94 }

  condition:
    any of them
}