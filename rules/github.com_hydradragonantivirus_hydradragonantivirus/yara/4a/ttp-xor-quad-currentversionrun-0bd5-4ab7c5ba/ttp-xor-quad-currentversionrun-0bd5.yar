rule TTP_XOR_QUAD_CurrentVersionRun_0bd5 {
  strings:
    $key_0bd5 = { 58 ba [2] 7c b4 [2] 57 98 [2] 79 ba [2] 6d a1 [2] 62 bb [2] 7c a6 [2] 7e a7 [2] 65 a1 [2] 79 a6 [2] 65 89 }

  condition:
    any of them
}