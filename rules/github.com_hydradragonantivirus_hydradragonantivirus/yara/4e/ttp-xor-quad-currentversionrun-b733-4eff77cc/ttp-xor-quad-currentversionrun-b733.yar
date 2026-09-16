rule TTP_XOR_QUAD_CurrentVersionRun_b733 {
  strings:
    $key_b733 = { e4 5c [2] c0 52 [2] eb 7e [2] c5 5c [2] d1 47 [2] de 5d [2] c0 40 [2] c2 41 [2] d9 47 [2] c5 40 [2] d9 6f }

  condition:
    any of them
}