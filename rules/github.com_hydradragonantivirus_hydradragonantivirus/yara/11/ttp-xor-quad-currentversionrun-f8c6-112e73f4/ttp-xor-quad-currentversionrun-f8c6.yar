rule TTP_XOR_QUAD_CurrentVersionRun_f8c6 {
  strings:
    $key_f8c6 = { ab a9 [2] 8f a7 [2] a4 8b [2] 8a a9 [2] 9e b2 [2] 91 a8 [2] 8f b5 [2] 8d b4 [2] 96 b2 [2] 8a b5 [2] 96 9a }

  condition:
    any of them
}