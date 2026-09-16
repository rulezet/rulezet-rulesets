rule TTP_XOR_QUAD_CurrentVersionRun_07b5 {
  strings:
    $key_07b5 = { 54 da [2] 70 d4 [2] 5b f8 [2] 75 da [2] 61 c1 [2] 6e db [2] 70 c6 [2] 72 c7 [2] 69 c1 [2] 75 c6 [2] 69 e9 }

  condition:
    any of them
}