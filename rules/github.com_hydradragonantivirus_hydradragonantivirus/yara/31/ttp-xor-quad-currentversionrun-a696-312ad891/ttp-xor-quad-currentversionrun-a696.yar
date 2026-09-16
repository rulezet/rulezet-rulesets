rule TTP_XOR_QUAD_CurrentVersionRun_a696 {
  strings:
    $key_a696 = { f5 f9 [2] d1 f7 [2] fa db [2] d4 f9 [2] c0 e2 [2] cf f8 [2] d1 e5 [2] d3 e4 [2] c8 e2 [2] d4 e5 [2] c8 ca }

  condition:
    any of them
}