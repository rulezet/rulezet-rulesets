rule TTP_XOR_QUAD_CurrentVersionRun_b72f {
  strings:
    $key_b72f = { e4 40 [2] c0 4e [2] eb 62 [2] c5 40 [2] d1 5b [2] de 41 [2] c0 5c [2] c2 5d [2] d9 5b [2] c5 5c [2] d9 73 }

  condition:
    any of them
}