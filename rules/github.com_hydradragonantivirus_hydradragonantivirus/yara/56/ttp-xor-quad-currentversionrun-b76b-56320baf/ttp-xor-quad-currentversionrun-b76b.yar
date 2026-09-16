rule TTP_XOR_QUAD_CurrentVersionRun_b76b {
  strings:
    $key_b76b = { e4 04 [2] c0 0a [2] eb 26 [2] c5 04 [2] d1 1f [2] de 05 [2] c0 18 [2] c2 19 [2] d9 1f [2] c5 18 [2] d9 37 }

  condition:
    any of them
}