rule TTP_XOR_QUAD_CurrentVersionRun_27d6 {
  strings:
    $key_27d6 = { 74 b9 [2] 50 b7 [2] 7b 9b [2] 55 b9 [2] 41 a2 [2] 4e b8 [2] 50 a5 [2] 52 a4 [2] 49 a2 [2] 55 a5 [2] 49 8a }

  condition:
    any of them
}