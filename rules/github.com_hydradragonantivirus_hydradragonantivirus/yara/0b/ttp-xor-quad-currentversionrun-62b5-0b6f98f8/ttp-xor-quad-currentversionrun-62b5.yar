rule TTP_XOR_QUAD_CurrentVersionRun_62b5 {
  strings:
    $key_62b5 = { 31 da [2] 15 d4 [2] 3e f8 [2] 10 da [2] 04 c1 [2] 0b db [2] 15 c6 [2] 17 c7 [2] 0c c1 [2] 10 c6 [2] 0c e9 }

  condition:
    any of them
}