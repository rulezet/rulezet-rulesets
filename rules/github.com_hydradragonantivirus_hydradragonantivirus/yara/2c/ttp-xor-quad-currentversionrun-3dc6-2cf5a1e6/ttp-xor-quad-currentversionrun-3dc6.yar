rule TTP_XOR_QUAD_CurrentVersionRun_3dc6 {
  strings:
    $key_3dc6 = { 6e a9 [2] 4a a7 [2] 61 8b [2] 4f a9 [2] 5b b2 [2] 54 a8 [2] 4a b5 [2] 48 b4 [2] 53 b2 [2] 4f b5 [2] 53 9a }

  condition:
    any of them
}