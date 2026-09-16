rule TTP_XOR_QUAD_CurrentVersionRun_bc9f {
  strings:
    $key_bc9f = { ef f0 [2] cb fe [2] e0 d2 [2] ce f0 [2] da eb [2] d5 f1 [2] cb ec [2] c9 ed [2] d2 eb [2] ce ec [2] d2 c3 }

  condition:
    any of them
}