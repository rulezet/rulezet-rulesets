rule TTP_XOR_QUAD_CurrentVersionRun_b5d5 {
  strings:
    $key_b5d5 = { e6 ba [2] c2 b4 [2] e9 98 [2] c7 ba [2] d3 a1 [2] dc bb [2] c2 a6 [2] c0 a7 [2] db a1 [2] c7 a6 [2] db 89 }

  condition:
    any of them
}