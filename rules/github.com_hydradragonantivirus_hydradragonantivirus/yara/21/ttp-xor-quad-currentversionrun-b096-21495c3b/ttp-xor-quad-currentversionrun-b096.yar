rule TTP_XOR_QUAD_CurrentVersionRun_b096 {
  strings:
    $key_b096 = { e3 f9 [2] c7 f7 [2] ec db [2] c2 f9 [2] d6 e2 [2] d9 f8 [2] c7 e5 [2] c5 e4 [2] de e2 [2] c2 e5 [2] de ca }

  condition:
    any of them
}