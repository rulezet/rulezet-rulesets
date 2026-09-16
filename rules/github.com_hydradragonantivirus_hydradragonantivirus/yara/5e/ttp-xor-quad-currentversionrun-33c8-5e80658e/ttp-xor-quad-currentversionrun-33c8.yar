rule TTP_XOR_QUAD_CurrentVersionRun_33c8 {
  strings:
    $key_33c8 = { 60 a7 [2] 44 a9 [2] 6f 85 [2] 41 a7 [2] 55 bc [2] 5a a6 [2] 44 bb [2] 46 ba [2] 5d bc [2] 41 bb [2] 5d 94 }

  condition:
    any of them
}