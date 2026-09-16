rule TTP_XOR_QUAD_CurrentVersionRun_b691 {
  strings:
    $key_b691 = { e5 fe [2] c1 f0 [2] ea dc [2] c4 fe [2] d0 e5 [2] df ff [2] c1 e2 [2] c3 e3 [2] d8 e5 [2] c4 e2 [2] d8 cd }

  condition:
    any of them
}