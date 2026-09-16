rule TTP_XOR_QUAD_CurrentVersionRun_13c9 {
  strings:
    $key_13c9 = { 40 a6 [2] 64 a8 [2] 4f 84 [2] 61 a6 [2] 75 bd [2] 7a a7 [2] 64 ba [2] 66 bb [2] 7d bd [2] 61 ba [2] 7d 95 }

  condition:
    any of them
}