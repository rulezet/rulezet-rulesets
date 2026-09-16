rule TTP_XOR_QUAD_CurrentVersionRun_b706 {
  strings:
    $key_b706 = { e4 69 [2] c0 67 [2] eb 4b [2] c5 69 [2] d1 72 [2] de 68 [2] c0 75 [2] c2 74 [2] d9 72 [2] c5 75 [2] d9 5a }

  condition:
    any of them
}