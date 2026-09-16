rule TTP_XOR_QUAD_CurrentVersionRun_b4f1 {
  strings:
    $key_b4f1 = { e7 9e [2] c3 90 [2] e8 bc [2] c6 9e [2] d2 85 [2] dd 9f [2] c3 82 [2] c1 83 [2] da 85 [2] c6 82 [2] da ad }

  condition:
    any of them
}