rule TTP_XOR_QUAD_CurrentVersionRun_20d6 {
  strings:
    $key_20d6 = { 73 b9 [2] 57 b7 [2] 7c 9b [2] 52 b9 [2] 46 a2 [2] 49 b8 [2] 57 a5 [2] 55 a4 [2] 4e a2 [2] 52 a5 [2] 4e 8a }

  condition:
    any of them
}