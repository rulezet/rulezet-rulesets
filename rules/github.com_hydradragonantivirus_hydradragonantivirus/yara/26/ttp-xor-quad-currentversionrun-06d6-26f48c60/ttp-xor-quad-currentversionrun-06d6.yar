rule TTP_XOR_QUAD_CurrentVersionRun_06d6 {
  strings:
    $key_06d6 = { 55 b9 [2] 71 b7 [2] 5a 9b [2] 74 b9 [2] 60 a2 [2] 6f b8 [2] 71 a5 [2] 73 a4 [2] 68 a2 [2] 74 a5 [2] 68 8a }

  condition:
    any of them
}