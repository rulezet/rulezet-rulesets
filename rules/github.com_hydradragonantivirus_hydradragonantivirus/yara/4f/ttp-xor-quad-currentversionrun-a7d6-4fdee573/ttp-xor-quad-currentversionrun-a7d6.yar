rule TTP_XOR_QUAD_CurrentVersionRun_a7d6 {
  strings:
    $key_a7d6 = { f4 b9 [2] d0 b7 [2] fb 9b [2] d5 b9 [2] c1 a2 [2] ce b8 [2] d0 a5 [2] d2 a4 [2] c9 a2 [2] d5 a5 [2] c9 8a }

  condition:
    any of them
}