rule TTP_XOR_QUAD_CurrentVersionRun_b76f {
  strings:
    $key_b76f = { e4 00 [2] c0 0e [2] eb 22 [2] c5 00 [2] d1 1b [2] de 01 [2] c0 1c [2] c2 1d [2] d9 1b [2] c5 1c [2] d9 33 }

  condition:
    any of them
}