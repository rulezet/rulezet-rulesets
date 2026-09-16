rule TTP_XOR_QUAD_CurrentVersionRun_1d73 {
  strings:
    $key_1d73 = { 4e 1c [2] 6a 12 [2] 41 3e [2] 6f 1c [2] 7b 07 [2] 74 1d [2] 6a 00 [2] 68 01 [2] 73 07 [2] 6f 00 [2] 73 2f }

  condition:
    any of them
}