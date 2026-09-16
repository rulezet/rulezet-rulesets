rule TTP_XOR_QUAD_CurrentVersionRun_6cc6 {
  strings:
    $key_6cc6 = { 3f a9 [2] 1b a7 [2] 30 8b [2] 1e a9 [2] 0a b2 [2] 05 a8 [2] 1b b5 [2] 19 b4 [2] 02 b2 [2] 1e b5 [2] 02 9a }

  condition:
    any of them
}