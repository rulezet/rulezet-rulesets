rule TTP_XOR_QUAD_CurrentVersionRun_47d6 {
  strings:
    $key_47d6 = { 14 b9 [2] 30 b7 [2] 1b 9b [2] 35 b9 [2] 21 a2 [2] 2e b8 [2] 30 a5 [2] 32 a4 [2] 29 a2 [2] 35 a5 [2] 29 8a }

  condition:
    any of them
}