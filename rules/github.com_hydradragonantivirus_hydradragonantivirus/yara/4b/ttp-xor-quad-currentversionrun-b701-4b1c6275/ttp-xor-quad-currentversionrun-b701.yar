rule TTP_XOR_QUAD_CurrentVersionRun_b701 {
  strings:
    $key_b701 = { e4 6e [2] c0 60 [2] eb 4c [2] c5 6e [2] d1 75 [2] de 6f [2] c0 72 [2] c2 73 [2] d9 75 [2] c5 72 [2] d9 5d }

  condition:
    any of them
}