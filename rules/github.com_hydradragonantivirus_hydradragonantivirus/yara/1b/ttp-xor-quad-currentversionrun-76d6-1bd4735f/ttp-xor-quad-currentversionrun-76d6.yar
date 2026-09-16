rule TTP_XOR_QUAD_CurrentVersionRun_76d6 {
  strings:
    $key_76d6 = { 25 b9 [2] 01 b7 [2] 2a 9b [2] 04 b9 [2] 10 a2 [2] 1f b8 [2] 01 a5 [2] 03 a4 [2] 18 a2 [2] 04 a5 [2] 18 8a }

  condition:
    any of them
}