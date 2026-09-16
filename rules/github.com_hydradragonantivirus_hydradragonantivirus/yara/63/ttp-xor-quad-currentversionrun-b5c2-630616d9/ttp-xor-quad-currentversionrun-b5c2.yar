rule TTP_XOR_QUAD_CurrentVersionRun_b5c2 {
  strings:
    $key_b5c2 = { e6 ad [2] c2 a3 [2] e9 8f [2] c7 ad [2] d3 b6 [2] dc ac [2] c2 b1 [2] c0 b0 [2] db b6 [2] c7 b1 [2] db 9e }

  condition:
    any of them
}