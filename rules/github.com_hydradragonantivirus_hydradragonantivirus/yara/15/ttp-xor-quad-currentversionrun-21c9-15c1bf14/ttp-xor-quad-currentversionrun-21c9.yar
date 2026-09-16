rule TTP_XOR_QUAD_CurrentVersionRun_21c9 {
  strings:
    $key_21c9 = { 72 a6 [2] 56 a8 [2] 7d 84 [2] 53 a6 [2] 47 bd [2] 48 a7 [2] 56 ba [2] 54 bb [2] 4f bd [2] 53 ba [2] 4f 95 }

  condition:
    any of them
}