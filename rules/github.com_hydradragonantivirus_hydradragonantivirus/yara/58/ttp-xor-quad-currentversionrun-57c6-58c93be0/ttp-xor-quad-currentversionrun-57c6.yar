rule TTP_XOR_QUAD_CurrentVersionRun_57c6 {
  strings:
    $key_57c6 = { 04 a9 [2] 20 a7 [2] 0b 8b [2] 25 a9 [2] 31 b2 [2] 3e a8 [2] 20 b5 [2] 22 b4 [2] 39 b2 [2] 25 b5 [2] 39 9a }

  condition:
    any of them
}