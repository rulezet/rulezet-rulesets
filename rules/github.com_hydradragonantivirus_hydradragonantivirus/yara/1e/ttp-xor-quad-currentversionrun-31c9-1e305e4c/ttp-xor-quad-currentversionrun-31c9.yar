rule TTP_XOR_QUAD_CurrentVersionRun_31c9 {
  strings:
    $key_31c9 = { 62 a6 [2] 46 a8 [2] 6d 84 [2] 43 a6 [2] 57 bd [2] 58 a7 [2] 46 ba [2] 44 bb [2] 5f bd [2] 43 ba [2] 5f 95 }

  condition:
    any of them
}