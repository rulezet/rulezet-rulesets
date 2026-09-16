rule TTP_XOR_QUAD_CurrentVersionRun_2bd5 {
  strings:
    $key_2bd5 = { 78 ba [2] 5c b4 [2] 77 98 [2] 59 ba [2] 4d a1 [2] 42 bb [2] 5c a6 [2] 5e a7 [2] 45 a1 [2] 59 a6 [2] 45 89 }

  condition:
    any of them
}