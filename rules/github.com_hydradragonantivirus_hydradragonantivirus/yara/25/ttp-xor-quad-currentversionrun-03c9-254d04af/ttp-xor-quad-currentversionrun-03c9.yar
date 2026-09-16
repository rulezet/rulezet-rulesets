rule TTP_XOR_QUAD_CurrentVersionRun_03c9 {
  strings:
    $key_03c9 = { 50 a6 [2] 74 a8 [2] 5f 84 [2] 71 a6 [2] 65 bd [2] 6a a7 [2] 74 ba [2] 76 bb [2] 6d bd [2] 71 ba [2] 6d 95 }

  condition:
    any of them
}