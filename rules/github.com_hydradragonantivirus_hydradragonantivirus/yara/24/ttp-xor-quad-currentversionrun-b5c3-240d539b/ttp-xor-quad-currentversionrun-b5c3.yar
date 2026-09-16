rule TTP_XOR_QUAD_CurrentVersionRun_b5c3 {
  strings:
    $key_b5c3 = { e6 ac [2] c2 a2 [2] e9 8e [2] c7 ac [2] d3 b7 [2] dc ad [2] c2 b0 [2] c0 b1 [2] db b7 [2] c7 b0 [2] db 9f }

  condition:
    any of them
}