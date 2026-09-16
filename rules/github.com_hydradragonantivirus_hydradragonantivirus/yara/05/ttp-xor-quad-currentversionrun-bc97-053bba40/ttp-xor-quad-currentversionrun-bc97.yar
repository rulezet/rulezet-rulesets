rule TTP_XOR_QUAD_CurrentVersionRun_bc97 {
  strings:
    $key_bc97 = { ef f8 [2] cb f6 [2] e0 da [2] ce f8 [2] da e3 [2] d5 f9 [2] cb e4 [2] c9 e5 [2] d2 e3 [2] ce e4 [2] d2 cb }

  condition:
    any of them
}