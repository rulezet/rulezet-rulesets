rule TTP_XOR_QUAD_CurrentVersionRun_b397 {
  strings:
    $key_b397 = { e0 f8 [2] c4 f6 [2] ef da [2] c1 f8 [2] d5 e3 [2] da f9 [2] c4 e4 [2] c6 e5 [2] dd e3 [2] c1 e4 [2] dd cb }

  condition:
    any of them
}