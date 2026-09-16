rule TTP_XOR_QUAD_CurrentVersionRun_b46c {
  strings:
    $key_b46c = { e7 03 [2] c3 0d [2] e8 21 [2] c6 03 [2] d2 18 [2] dd 02 [2] c3 1f [2] c1 1e [2] da 18 [2] c6 1f [2] da 30 }

  condition:
    any of them
}