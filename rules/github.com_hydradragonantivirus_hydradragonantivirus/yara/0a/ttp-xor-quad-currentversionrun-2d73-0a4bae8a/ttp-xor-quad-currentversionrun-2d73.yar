rule TTP_XOR_QUAD_CurrentVersionRun_2d73 {
  strings:
    $key_2d73 = { 7e 1c [2] 5a 12 [2] 71 3e [2] 5f 1c [2] 4b 07 [2] 44 1d [2] 5a 00 [2] 58 01 [2] 43 07 [2] 5f 00 [2] 43 2f }

  condition:
    any of them
}