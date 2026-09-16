rule TTP_XOR_QUAD_CurrentVersionRun_27c8 {
  strings:
    $key_27c8 = { 74 a7 [2] 50 a9 [2] 7b 85 [2] 55 a7 [2] 41 bc [2] 4e a6 [2] 50 bb [2] 52 ba [2] 49 bc [2] 55 bb [2] 49 94 }

  condition:
    any of them
}