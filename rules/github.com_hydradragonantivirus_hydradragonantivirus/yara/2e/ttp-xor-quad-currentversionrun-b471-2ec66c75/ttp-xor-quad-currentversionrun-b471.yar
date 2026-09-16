rule TTP_XOR_QUAD_CurrentVersionRun_b471 {
  strings:
    $key_b471 = { e7 1e [2] c3 10 [2] e8 3c [2] c6 1e [2] d2 05 [2] dd 1f [2] c3 02 [2] c1 03 [2] da 05 [2] c6 02 [2] da 2d }

  condition:
    any of them
}