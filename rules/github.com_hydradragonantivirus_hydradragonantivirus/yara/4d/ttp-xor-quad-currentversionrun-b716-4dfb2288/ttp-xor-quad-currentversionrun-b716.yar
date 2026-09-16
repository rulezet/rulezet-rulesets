rule TTP_XOR_QUAD_CurrentVersionRun_b716 {
  strings:
    $key_b716 = { e4 79 [2] c0 77 [2] eb 5b [2] c5 79 [2] d1 62 [2] de 78 [2] c0 65 [2] c2 64 [2] d9 62 [2] c5 65 [2] d9 4a }

  condition:
    any of them
}