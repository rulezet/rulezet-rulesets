rule TTP_XOR_QUAD_CurrentVersionRun_5bd5 {
  strings:
    $key_5bd5 = { 08 ba [2] 2c b4 [2] 07 98 [2] 29 ba [2] 3d a1 [2] 32 bb [2] 2c a6 [2] 2e a7 [2] 35 a1 [2] 29 a6 [2] 35 89 }

  condition:
    any of them
}