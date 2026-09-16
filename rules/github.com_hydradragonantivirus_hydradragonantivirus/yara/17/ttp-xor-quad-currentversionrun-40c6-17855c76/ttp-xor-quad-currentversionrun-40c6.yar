rule TTP_XOR_QUAD_CurrentVersionRun_40c6 {
  strings:
    $key_40c6 = { 13 a9 [2] 37 a7 [2] 1c 8b [2] 32 a9 [2] 26 b2 [2] 29 a8 [2] 37 b5 [2] 35 b4 [2] 2e b2 [2] 32 b5 [2] 2e 9a }

  condition:
    any of them
}