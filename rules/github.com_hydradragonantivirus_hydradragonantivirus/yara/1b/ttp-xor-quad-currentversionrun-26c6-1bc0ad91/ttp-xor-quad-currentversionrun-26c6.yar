rule TTP_XOR_QUAD_CurrentVersionRun_26c6 {
  strings:
    $key_26c6 = { 75 a9 [2] 51 a7 [2] 7a 8b [2] 54 a9 [2] 40 b2 [2] 4f a8 [2] 51 b5 [2] 53 b4 [2] 48 b2 [2] 54 b5 [2] 48 9a }

  condition:
    any of them
}