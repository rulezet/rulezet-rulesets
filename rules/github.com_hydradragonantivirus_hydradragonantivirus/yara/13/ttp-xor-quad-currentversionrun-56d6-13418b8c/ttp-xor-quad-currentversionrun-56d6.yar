rule TTP_XOR_QUAD_CurrentVersionRun_56d6 {
  strings:
    $key_56d6 = { 05 b9 [2] 21 b7 [2] 0a 9b [2] 24 b9 [2] 30 a2 [2] 3f b8 [2] 21 a5 [2] 23 a4 [2] 38 a2 [2] 24 a5 [2] 38 8a }

  condition:
    any of them
}