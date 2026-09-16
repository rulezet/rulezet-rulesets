rule TTP_XOR_QUAD_CurrentVersionRun_a7c7 {
  strings:
    $key_a7c7 = { f4 a8 [2] d0 a6 [2] fb 8a [2] d5 a8 [2] c1 b3 [2] ce a9 [2] d0 b4 [2] d2 b5 [2] c9 b3 [2] d5 b4 [2] c9 9b }

  condition:
    any of them
}