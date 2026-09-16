rule TTP_XOR_QUAD_CurrentVersionRun_4ec9 {
  strings:
    $key_4ec9 = { 1d a6 [2] 39 a8 [2] 12 84 [2] 3c a6 [2] 28 bd [2] 27 a7 [2] 39 ba [2] 3b bb [2] 20 bd [2] 3c ba [2] 20 95 }

  condition:
    any of them
}