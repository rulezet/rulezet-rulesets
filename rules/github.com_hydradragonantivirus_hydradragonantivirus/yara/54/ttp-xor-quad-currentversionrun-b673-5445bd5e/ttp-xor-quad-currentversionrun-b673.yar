rule TTP_XOR_QUAD_CurrentVersionRun_b673 {
  strings:
    $key_b673 = { e5 1c [2] c1 12 [2] ea 3e [2] c4 1c [2] d0 07 [2] df 1d [2] c1 00 [2] c3 01 [2] d8 07 [2] c4 00 [2] d8 2f }

  condition:
    any of them
}