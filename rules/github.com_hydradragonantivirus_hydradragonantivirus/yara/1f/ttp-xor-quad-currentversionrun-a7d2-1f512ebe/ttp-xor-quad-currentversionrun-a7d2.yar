rule TTP_XOR_QUAD_CurrentVersionRun_a7d2 {
  strings:
    $key_a7d2 = { f4 bd [2] d0 b3 [2] fb 9f [2] d5 bd [2] c1 a6 [2] ce bc [2] d0 a1 [2] d2 a0 [2] c9 a6 [2] d5 a1 [2] c9 8e }

  condition:
    any of them
}