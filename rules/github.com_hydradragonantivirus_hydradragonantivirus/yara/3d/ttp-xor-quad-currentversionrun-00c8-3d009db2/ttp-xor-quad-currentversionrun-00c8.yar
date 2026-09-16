rule TTP_XOR_QUAD_CurrentVersionRun_00c8 {
  strings:
    $key_00c8 = { 53 a7 [2] 77 a9 [2] 5c 85 [2] 72 a7 [2] 66 bc [2] 69 a6 [2] 77 bb [2] 75 ba [2] 6e bc [2] 72 bb [2] 6e 94 }

  condition:
    any of them
}