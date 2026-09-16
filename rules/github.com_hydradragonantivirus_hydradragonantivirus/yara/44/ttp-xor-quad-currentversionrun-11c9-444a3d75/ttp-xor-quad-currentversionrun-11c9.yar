rule TTP_XOR_QUAD_CurrentVersionRun_11c9 {
  strings:
    $key_11c9 = { 42 a6 [2] 66 a8 [2] 4d 84 [2] 63 a6 [2] 77 bd [2] 78 a7 [2] 66 ba [2] 64 bb [2] 7f bd [2] 63 ba [2] 7f 95 }

  condition:
    any of them
}