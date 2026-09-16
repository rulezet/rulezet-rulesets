rule TTP_XOR_QUAD_CurrentVersionRun_75c8 {
  strings:
    $key_75c8 = { 26 a7 [2] 02 a9 [2] 29 85 [2] 07 a7 [2] 13 bc [2] 1c a6 [2] 02 bb [2] 00 ba [2] 1b bc [2] 07 bb [2] 1b 94 }

  condition:
    any of them
}