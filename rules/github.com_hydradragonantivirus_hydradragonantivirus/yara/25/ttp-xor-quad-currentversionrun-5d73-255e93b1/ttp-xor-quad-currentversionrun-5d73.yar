rule TTP_XOR_QUAD_CurrentVersionRun_5d73 {
  strings:
    $key_5d73 = { 0e 1c [2] 2a 12 [2] 01 3e [2] 2f 1c [2] 3b 07 [2] 34 1d [2] 2a 00 [2] 28 01 [2] 33 07 [2] 2f 00 [2] 33 2f }

  condition:
    any of them
}