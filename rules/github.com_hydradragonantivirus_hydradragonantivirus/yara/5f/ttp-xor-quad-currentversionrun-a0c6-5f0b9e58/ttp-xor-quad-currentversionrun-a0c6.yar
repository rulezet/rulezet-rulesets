rule TTP_XOR_QUAD_CurrentVersionRun_a0c6 {
  strings:
    $key_a0c6 = { f3 a9 [2] d7 a7 [2] fc 8b [2] d2 a9 [2] c6 b2 [2] c9 a8 [2] d7 b5 [2] d5 b4 [2] ce b2 [2] d2 b5 [2] ce 9a }

  condition:
    any of them
}