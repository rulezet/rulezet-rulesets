rule TTP_XOR_QUAD_CurrentVersionRun_57c8 {
  strings:
    $key_57c8 = { 04 a7 [2] 20 a9 [2] 0b 85 [2] 25 a7 [2] 31 bc [2] 3e a6 [2] 20 bb [2] 22 ba [2] 39 bc [2] 25 bb [2] 39 94 }

  condition:
    any of them
}