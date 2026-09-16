rule TTP_XOR_QUAD_CurrentVersionRun_0ec8 {
  strings:
    $key_0ec8 = { 5d a7 [2] 79 a9 [2] 52 85 [2] 7c a7 [2] 68 bc [2] 67 a6 [2] 79 bb [2] 7b ba [2] 60 bc [2] 7c bb [2] 60 94 }

  condition:
    any of them
}