rule TTP_XOR_QUAD_CurrentVersionRun_b36e {
  strings:
    $key_b36e = { e0 01 [2] c4 0f [2] ef 23 [2] c1 01 [2] d5 1a [2] da 00 [2] c4 1d [2] c6 1c [2] dd 1a [2] c1 1d [2] dd 32 }

  condition:
    any of them
}