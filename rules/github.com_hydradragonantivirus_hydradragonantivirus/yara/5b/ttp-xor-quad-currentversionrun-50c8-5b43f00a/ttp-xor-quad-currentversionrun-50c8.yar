rule TTP_XOR_QUAD_CurrentVersionRun_50c8 {
  strings:
    $key_50c8 = { 03 a7 [2] 27 a9 [2] 0c 85 [2] 22 a7 [2] 36 bc [2] 39 a6 [2] 27 bb [2] 25 ba [2] 3e bc [2] 22 bb [2] 3e 94 }

  condition:
    any of them
}