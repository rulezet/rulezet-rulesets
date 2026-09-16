rule TTP_XOR_QUAD_CurrentVersionRun_f1c9 {
  strings:
    $key_f1c9 = { a2 a6 [2] 86 a8 [2] ad 84 [2] 83 a6 [2] 97 bd [2] 98 a7 [2] 86 ba [2] 84 bb [2] 9f bd [2] 83 ba [2] 9f 95 }

  condition:
    any of them
}