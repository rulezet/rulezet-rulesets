rule TTP_XOR_QUAD_CurrentVersionRun_10d6 {
  strings:
    $key_10d6 = { 43 b9 [2] 67 b7 [2] 4c 9b [2] 62 b9 [2] 76 a2 [2] 79 b8 [2] 67 a5 [2] 65 a4 [2] 7e a2 [2] 62 a5 [2] 7e 8a }

  condition:
    any of them
}