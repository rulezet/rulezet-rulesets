rule TTP_XOR_QUAD_CurrentVersionRun_a0c7 {
  strings:
    $key_a0c7 = { f3 a8 [2] d7 a6 [2] fc 8a [2] d2 a8 [2] c6 b3 [2] c9 a9 [2] d7 b4 [2] d5 b5 [2] ce b3 [2] d2 b4 [2] ce 9b }

  condition:
    any of them
}