rule TTP_XOR_QUAD_CurrentVersionRun_b5c8 {
  strings:
    $key_b5c8 = { e6 a7 [2] c2 a9 [2] e9 85 [2] c7 a7 [2] d3 bc [2] dc a6 [2] c2 bb [2] c0 ba [2] db bc [2] c7 bb [2] db 94 }

  condition:
    any of them
}