rule TTP_XOR_QUAD_CurrentVersionRun_b76e {
  strings:
    $key_b76e = { e4 01 [2] c0 0f [2] eb 23 [2] c5 01 [2] d1 1a [2] de 00 [2] c0 1d [2] c2 1c [2] d9 1a [2] c5 1d [2] d9 32 }

  condition:
    any of them
}