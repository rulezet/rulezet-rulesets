rule TTP_XOR_QUAD_CurrentVersionRun_26c7 {
  strings:
    $key_26c7 = { 75 a8 [2] 51 a6 [2] 7a 8a [2] 54 a8 [2] 40 b3 [2] 4f a9 [2] 51 b4 [2] 53 b5 [2] 48 b3 [2] 54 b4 [2] 48 9b }

  condition:
    any of them
}