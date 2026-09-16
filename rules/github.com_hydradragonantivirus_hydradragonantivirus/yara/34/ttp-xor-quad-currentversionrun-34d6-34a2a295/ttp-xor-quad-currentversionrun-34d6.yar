rule TTP_XOR_QUAD_CurrentVersionRun_34d6 {
  strings:
    $key_34d6 = { 67 b9 [2] 43 b7 [2] 68 9b [2] 46 b9 [2] 52 a2 [2] 5d b8 [2] 43 a5 [2] 41 a4 [2] 5a a2 [2] 46 a5 [2] 5a 8a }

  condition:
    any of them
}