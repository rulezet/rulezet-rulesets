rule TTP_XOR_QUAD_CurrentVersionRun_0ad6 {
  strings:
    $key_0ad6 = { 59 b9 [2] 7d b7 [2] 56 9b [2] 78 b9 [2] 6c a2 [2] 63 b8 [2] 7d a5 [2] 7f a4 [2] 64 a2 [2] 78 a5 [2] 64 8a }

  condition:
    any of them
}