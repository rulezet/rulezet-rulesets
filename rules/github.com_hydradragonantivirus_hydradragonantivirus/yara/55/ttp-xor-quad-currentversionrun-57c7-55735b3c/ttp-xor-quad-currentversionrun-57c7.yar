rule TTP_XOR_QUAD_CurrentVersionRun_57c7 {
  strings:
    $key_57c7 = { 04 a8 [2] 20 a6 [2] 0b 8a [2] 25 a8 [2] 31 b3 [2] 3e a9 [2] 20 b4 [2] 22 b5 [2] 39 b3 [2] 25 b4 [2] 39 9b }

  condition:
    any of them
}