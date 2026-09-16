rule TTP_XOR_QUAD_CurrentVersionRun_56b5 {
  strings:
    $key_56b5 = { 05 da [2] 21 d4 [2] 0a f8 [2] 24 da [2] 30 c1 [2] 3f db [2] 21 c6 [2] 23 c7 [2] 38 c1 [2] 24 c6 [2] 38 e9 }

  condition:
    any of them
}