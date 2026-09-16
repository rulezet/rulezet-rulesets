rule TTP_XOR_QUAD_CurrentVersionRun_b403 {
  strings:
    $key_b403 = { e7 6c [2] c3 62 [2] e8 4e [2] c6 6c [2] d2 77 [2] dd 6d [2] c3 70 [2] c1 71 [2] da 77 [2] c6 70 [2] da 5f }

  condition:
    any of them
}