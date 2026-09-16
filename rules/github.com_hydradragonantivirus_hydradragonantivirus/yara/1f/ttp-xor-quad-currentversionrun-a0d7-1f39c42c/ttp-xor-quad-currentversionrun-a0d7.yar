rule TTP_XOR_QUAD_CurrentVersionRun_a0d7 {
  strings:
    $key_a0d7 = { f3 b8 [2] d7 b6 [2] fc 9a [2] d2 b8 [2] c6 a3 [2] c9 b9 [2] d7 a4 [2] d5 a5 [2] ce a3 [2] d2 a4 [2] ce 8b }

  condition:
    any of them
}