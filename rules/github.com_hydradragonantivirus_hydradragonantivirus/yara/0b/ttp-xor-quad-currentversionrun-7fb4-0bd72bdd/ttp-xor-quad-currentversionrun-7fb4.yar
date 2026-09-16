rule TTP_XOR_QUAD_CurrentVersionRun_7fb4 {
  strings:
    $key_7fb4 = { 2c db [2] 08 d5 [2] 23 f9 [2] 0d db [2] 19 c0 [2] 16 da [2] 08 c7 [2] 0a c6 [2] 11 c0 [2] 0d c7 [2] 11 e8 }

  condition:
    any of them
}