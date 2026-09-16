rule TTP_XOR_QUAD_CurrentVersionRun_b7ec {
  strings:
    $key_b7ec = { e4 83 [2] c0 8d [2] eb a1 [2] c5 83 [2] d1 98 [2] de 82 [2] c0 9f [2] c2 9e [2] d9 98 [2] c5 9f [2] d9 b0 }

  condition:
    any of them
}