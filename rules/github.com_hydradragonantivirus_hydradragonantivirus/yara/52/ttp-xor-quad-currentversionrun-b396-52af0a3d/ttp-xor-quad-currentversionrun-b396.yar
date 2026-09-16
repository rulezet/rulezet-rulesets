rule TTP_XOR_QUAD_CurrentVersionRun_b396 {
  strings:
    $key_b396 = { e0 f9 [2] c4 f7 [2] ef db [2] c1 f9 [2] d5 e2 [2] da f8 [2] c4 e5 [2] c6 e4 [2] dd e2 [2] c1 e5 [2] dd ca }

  condition:
    any of them
}