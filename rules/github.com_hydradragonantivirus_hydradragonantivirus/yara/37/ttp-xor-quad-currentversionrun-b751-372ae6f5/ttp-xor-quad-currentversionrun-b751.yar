rule TTP_XOR_QUAD_CurrentVersionRun_b751 {
  strings:
    $key_b751 = { e4 3e [2] c0 30 [2] eb 1c [2] c5 3e [2] d1 25 [2] de 3f [2] c0 22 [2] c2 23 [2] d9 25 [2] c5 22 [2] d9 0d }

  condition:
    any of them
}