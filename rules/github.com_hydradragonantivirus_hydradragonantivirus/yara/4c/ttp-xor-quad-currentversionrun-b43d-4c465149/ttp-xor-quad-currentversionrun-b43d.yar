rule TTP_XOR_QUAD_CurrentVersionRun_b43d {
  strings:
    $key_b43d = { e7 52 [2] c3 5c [2] e8 70 [2] c6 52 [2] d2 49 [2] dd 53 [2] c3 4e [2] c1 4f [2] da 49 [2] c6 4e [2] da 61 }

  condition:
    any of them
}