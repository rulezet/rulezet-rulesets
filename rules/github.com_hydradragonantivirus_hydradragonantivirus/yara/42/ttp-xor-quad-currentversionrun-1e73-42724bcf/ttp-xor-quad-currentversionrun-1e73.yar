rule TTP_XOR_QUAD_CurrentVersionRun_1e73 {
  strings:
    $key_1e73 = { 4d 1c [2] 69 12 [2] 42 3e [2] 6c 1c [2] 78 07 [2] 77 1d [2] 69 00 [2] 6b 01 [2] 70 07 [2] 6c 00 [2] 70 2f }

  condition:
    any of them
}