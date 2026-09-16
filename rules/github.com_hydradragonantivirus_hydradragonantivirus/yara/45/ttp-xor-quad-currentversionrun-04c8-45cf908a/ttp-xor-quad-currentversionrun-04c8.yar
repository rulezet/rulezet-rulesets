rule TTP_XOR_QUAD_CurrentVersionRun_04c8 {
  strings:
    $key_04c8 = { 57 a7 [2] 73 a9 [2] 58 85 [2] 76 a7 [2] 62 bc [2] 6d a6 [2] 73 bb [2] 71 ba [2] 6a bc [2] 76 bb [2] 6a 94 }

  condition:
    any of them
}