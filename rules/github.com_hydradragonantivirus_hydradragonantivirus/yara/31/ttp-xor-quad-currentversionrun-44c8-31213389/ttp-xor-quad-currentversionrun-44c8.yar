rule TTP_XOR_QUAD_CurrentVersionRun_44c8 {
  strings:
    $key_44c8 = { 17 a7 [2] 33 a9 [2] 18 85 [2] 36 a7 [2] 22 bc [2] 2d a6 [2] 33 bb [2] 31 ba [2] 2a bc [2] 36 bb [2] 2a 94 }

  condition:
    any of them
}