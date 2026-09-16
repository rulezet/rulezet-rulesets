rule TTP_XOR_QUAD_CurrentVersionRun_a7d7 {
  strings:
    $key_a7d7 = { f4 b8 [2] d0 b6 [2] fb 9a [2] d5 b8 [2] c1 a3 [2] ce b9 [2] d0 a4 [2] d2 a5 [2] c9 a3 [2] d5 a4 [2] c9 8b }

  condition:
    any of them
}