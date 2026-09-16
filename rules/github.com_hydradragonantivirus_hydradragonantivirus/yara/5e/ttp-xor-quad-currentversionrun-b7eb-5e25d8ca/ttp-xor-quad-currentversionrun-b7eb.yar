rule TTP_XOR_QUAD_CurrentVersionRun_b7eb {
  strings:
    $key_b7eb = { e4 84 [2] c0 8a [2] eb a6 [2] c5 84 [2] d1 9f [2] de 85 [2] c0 98 [2] c2 99 [2] d9 9f [2] c5 98 [2] d9 b7 }

  condition:
    any of them
}