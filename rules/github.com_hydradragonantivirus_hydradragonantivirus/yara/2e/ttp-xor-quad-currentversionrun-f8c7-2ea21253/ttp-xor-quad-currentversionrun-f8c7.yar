rule TTP_XOR_QUAD_CurrentVersionRun_f8c7 {
  strings:
    $key_f8c7 = { ab a8 [2] 8f a6 [2] a4 8a [2] 8a a8 [2] 9e b3 [2] 91 a9 [2] 8f b4 [2] 8d b5 [2] 96 b3 [2] 8a b4 [2] 96 9b }

  condition:
    any of them
}