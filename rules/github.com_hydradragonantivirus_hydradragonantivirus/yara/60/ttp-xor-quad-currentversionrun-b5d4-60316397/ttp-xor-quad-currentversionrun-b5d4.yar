rule TTP_XOR_QUAD_CurrentVersionRun_b5d4 {
  strings:
    $key_b5d4 = { e6 bb [2] c2 b5 [2] e9 99 [2] c7 bb [2] d3 a0 [2] dc ba [2] c2 a7 [2] c0 a6 [2] db a0 [2] c7 a7 [2] db 88 }

  condition:
    any of them
}