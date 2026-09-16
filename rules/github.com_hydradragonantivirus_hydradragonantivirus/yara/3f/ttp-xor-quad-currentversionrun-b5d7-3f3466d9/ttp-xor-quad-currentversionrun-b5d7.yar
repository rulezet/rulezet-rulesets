rule TTP_XOR_QUAD_CurrentVersionRun_b5d7 {
  strings:
    $key_b5d7 = { e6 b8 [2] c2 b6 [2] e9 9a [2] c7 b8 [2] d3 a3 [2] dc b9 [2] c2 a4 [2] c0 a5 [2] db a3 [2] c7 a4 [2] db 8b }

  condition:
    any of them
}