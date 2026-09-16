rule TTP_XOR_QUAD_CurrentVersionRun_26c9 {
  strings:
    $key_26c9 = { 75 a6 [2] 51 a8 [2] 7a 84 [2] 54 a6 [2] 40 bd [2] 4f a7 [2] 51 ba [2] 53 bb [2] 48 bd [2] 54 ba [2] 48 95 }

  condition:
    any of them
}