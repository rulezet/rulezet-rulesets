rule TTP_XOR_QUAD_CurrentVersionRun_64b5 {
  strings:
    $key_64b5 = { 37 da [2] 13 d4 [2] 38 f8 [2] 16 da [2] 02 c1 [2] 0d db [2] 13 c6 [2] 11 c7 [2] 0a c1 [2] 16 c6 [2] 0a e9 }

  condition:
    any of them
}