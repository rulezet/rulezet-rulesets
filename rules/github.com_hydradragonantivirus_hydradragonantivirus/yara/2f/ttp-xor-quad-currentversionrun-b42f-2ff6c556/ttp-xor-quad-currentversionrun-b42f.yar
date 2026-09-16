rule TTP_XOR_QUAD_CurrentVersionRun_b42f {
  strings:
    $key_b42f = { e7 40 [2] c3 4e [2] e8 62 [2] c6 40 [2] d2 5b [2] dd 41 [2] c3 5c [2] c1 5d [2] da 5b [2] c6 5c [2] da 73 }

  condition:
    any of them
}