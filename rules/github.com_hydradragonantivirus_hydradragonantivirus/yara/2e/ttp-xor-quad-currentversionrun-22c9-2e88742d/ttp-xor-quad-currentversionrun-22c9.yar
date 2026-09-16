rule TTP_XOR_QUAD_CurrentVersionRun_22c9 {
  strings:
    $key_22c9 = { 71 a6 [2] 55 a8 [2] 7e 84 [2] 50 a6 [2] 44 bd [2] 4b a7 [2] 55 ba [2] 57 bb [2] 4c bd [2] 50 ba [2] 4c 95 }

  condition:
    any of them
}