rule TTP_XOR_QUAD_CurrentVersionRun_14c8 {
  strings:
    $key_14c8 = { 47 a7 [2] 63 a9 [2] 48 85 [2] 66 a7 [2] 72 bc [2] 7d a6 [2] 63 bb [2] 61 ba [2] 7a bc [2] 66 bb [2] 7a 94 }

  condition:
    any of them
}