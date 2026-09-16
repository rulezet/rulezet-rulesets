rule TTP_XOR_QUAD_CurrentVersionRun_b4fc {
  strings:
    $key_b4fc = { e7 93 [2] c3 9d [2] e8 b1 [2] c6 93 [2] d2 88 [2] dd 92 [2] c3 8f [2] c1 8e [2] da 88 [2] c6 8f [2] da a0 }

  condition:
    any of them
}