rule TTP_XOR_QUAD_CurrentVersionRun_b6f1 {
  strings:
    $key_b6f1 = { e5 9e [2] c1 90 [2] ea bc [2] c4 9e [2] d0 85 [2] df 9f [2] c1 82 [2] c3 83 [2] d8 85 [2] c4 82 [2] d8 ad }

  condition:
    any of them
}