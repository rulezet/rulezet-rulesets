rule TTP_XOR_QUAD_CurrentVersionRun_bc8d {
  strings:
    $key_bc8d = { ef e2 [2] cb ec [2] e0 c0 [2] ce e2 [2] da f9 [2] d5 e3 [2] cb fe [2] c9 ff [2] d2 f9 [2] ce fe [2] d2 d1 }

  condition:
    any of them
}