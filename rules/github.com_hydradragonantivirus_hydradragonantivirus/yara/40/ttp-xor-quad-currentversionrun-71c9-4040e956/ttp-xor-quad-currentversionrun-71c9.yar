rule TTP_XOR_QUAD_CurrentVersionRun_71c9 {
  strings:
    $key_71c9 = { 22 a6 [2] 06 a8 [2] 2d 84 [2] 03 a6 [2] 17 bd [2] 18 a7 [2] 06 ba [2] 04 bb [2] 1f bd [2] 03 ba [2] 1f 95 }

  condition:
    any of them
}