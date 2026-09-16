rule TTP_XOR_QUAD_CurrentVersionRun_36b5 {
  strings:
    $key_36b5 = { 65 da [2] 41 d4 [2] 6a f8 [2] 44 da [2] 50 c1 [2] 5f db [2] 41 c6 [2] 43 c7 [2] 58 c1 [2] 44 c6 [2] 58 e9 }

  condition:
    any of them
}