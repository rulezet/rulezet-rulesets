rule TTP_XOR_QUAD_CurrentVersionRun_5ec9 {
  strings:
    $key_5ec9 = { 0d a6 [2] 29 a8 [2] 02 84 [2] 2c a6 [2] 38 bd [2] 37 a7 [2] 29 ba [2] 2b bb [2] 30 bd [2] 2c ba [2] 30 95 }

  condition:
    any of them
}