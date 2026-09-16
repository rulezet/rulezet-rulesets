rule TTP_XOR_QUAD_CurrentVersionRun_b5d2 {
  strings:
    $key_b5d2 = { e6 bd [2] c2 b3 [2] e9 9f [2] c7 bd [2] d3 a6 [2] dc bc [2] c2 a1 [2] c0 a0 [2] db a6 [2] c7 a1 [2] db 8e }

  condition:
    any of them
}