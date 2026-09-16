rule TTP_XOR_QUAD_CurrentVersionRun_32b5 {
  strings:
    $key_32b5 = { 61 da [2] 45 d4 [2] 6e f8 [2] 40 da [2] 54 c1 [2] 5b db [2] 45 c6 [2] 47 c7 [2] 5c c1 [2] 40 c6 [2] 5c e9 }

  condition:
    any of them
}