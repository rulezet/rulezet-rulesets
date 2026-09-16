rule TTP_XOR_QUAD_CurrentVersionRun_16c6 {
  strings:
    $key_16c6 = { 45 a9 [2] 61 a7 [2] 4a 8b [2] 64 a9 [2] 70 b2 [2] 7f a8 [2] 61 b5 [2] 63 b4 [2] 78 b2 [2] 64 b5 [2] 78 9a }

  condition:
    any of them
}