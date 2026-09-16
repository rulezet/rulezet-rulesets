rule TTP_XOR_QUAD_CurrentVersionRun_b46f {
  strings:
    $key_b46f = { e7 00 [2] c3 0e [2] e8 22 [2] c6 00 [2] d2 1b [2] dd 01 [2] c3 1c [2] c1 1d [2] da 1b [2] c6 1c [2] da 33 }

  condition:
    any of them
}