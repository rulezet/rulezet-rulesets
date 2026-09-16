rule TTP_XOR_QUAD_CurrentVersionRun_2bd4 {
  strings:
    $key_2bd4 = { 78 bb [2] 5c b5 [2] 77 99 [2] 59 bb [2] 4d a0 [2] 42 ba [2] 5c a7 [2] 5e a6 [2] 45 a0 [2] 59 a7 [2] 45 88 }

  condition:
    any of them
}