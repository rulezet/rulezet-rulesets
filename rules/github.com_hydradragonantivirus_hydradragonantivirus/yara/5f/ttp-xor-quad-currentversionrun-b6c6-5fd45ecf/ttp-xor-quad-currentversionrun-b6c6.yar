rule TTP_XOR_QUAD_CurrentVersionRun_b6c6 {
  strings:
    $key_b6c6 = { e5 a9 [2] c1 a7 [2] ea 8b [2] c4 a9 [2] d0 b2 [2] df a8 [2] c1 b5 [2] c3 b4 [2] d8 b2 [2] c4 b5 [2] d8 9a }

  condition:
    any of them
}