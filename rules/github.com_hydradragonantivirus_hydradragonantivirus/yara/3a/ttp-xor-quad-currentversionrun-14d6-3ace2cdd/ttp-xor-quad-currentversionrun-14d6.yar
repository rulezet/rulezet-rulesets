rule TTP_XOR_QUAD_CurrentVersionRun_14d6 {
  strings:
    $key_14d6 = { 47 b9 [2] 63 b7 [2] 48 9b [2] 66 b9 [2] 72 a2 [2] 7d b8 [2] 63 a5 [2] 61 a4 [2] 7a a2 [2] 66 a5 [2] 7a 8a }

  condition:
    any of them
}