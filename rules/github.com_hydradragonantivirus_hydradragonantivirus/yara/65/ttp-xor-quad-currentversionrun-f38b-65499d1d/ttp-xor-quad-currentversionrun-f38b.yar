rule TTP_XOR_QUAD_CurrentVersionRun_f38b {
  strings:
    $key_f38b = { a0 e4 [2] 84 ea [2] af c6 [2] 81 e4 [2] 95 ff [2] 9a e5 [2] 84 f8 [2] 86 f9 [2] 9d ff [2] 81 f8 [2] 9d d7 }

  condition:
    any of them
}