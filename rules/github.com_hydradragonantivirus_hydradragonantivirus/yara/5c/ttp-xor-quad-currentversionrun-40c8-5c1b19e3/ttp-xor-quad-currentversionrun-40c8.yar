rule TTP_XOR_QUAD_CurrentVersionRun_40c8 {
  strings:
    $key_40c8 = { 13 a7 [2] 37 a9 [2] 1c 85 [2] 32 a7 [2] 26 bc [2] 29 a6 [2] 37 bb [2] 35 ba [2] 2e bc [2] 32 bb [2] 2e 94 }

  condition:
    any of them
}