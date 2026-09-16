rule TTP_XOR_QUAD_CurrentVersionRun_b40f {
  strings:
    $key_b40f = { e7 60 [2] c3 6e [2] e8 42 [2] c6 60 [2] d2 7b [2] dd 61 [2] c3 7c [2] c1 7d [2] da 7b [2] c6 7c [2] da 53 }

  condition:
    any of them
}