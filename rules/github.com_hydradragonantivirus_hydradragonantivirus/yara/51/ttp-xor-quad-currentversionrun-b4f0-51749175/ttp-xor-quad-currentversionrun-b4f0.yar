rule TTP_XOR_QUAD_CurrentVersionRun_b4f0 {
  strings:
    $key_b4f0 = { e7 9f [2] c3 91 [2] e8 bd [2] c6 9f [2] d2 84 [2] dd 9e [2] c3 83 [2] c1 82 [2] da 84 [2] c6 83 [2] da ac }

  condition:
    any of them
}