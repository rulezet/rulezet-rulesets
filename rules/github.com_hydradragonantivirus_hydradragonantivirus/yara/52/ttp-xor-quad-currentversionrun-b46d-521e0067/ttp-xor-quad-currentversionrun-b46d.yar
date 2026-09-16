rule TTP_XOR_QUAD_CurrentVersionRun_b46d {
  strings:
    $key_b46d = { e7 02 [2] c3 0c [2] e8 20 [2] c6 02 [2] d2 19 [2] dd 03 [2] c3 1e [2] c1 1f [2] da 19 [2] c6 1e [2] da 31 }

  condition:
    any of them
}