rule TTP_XOR_QUAD_CurrentVersionRun_4e73 {
  strings:
    $key_4e73 = { 1d 1c [2] 39 12 [2] 12 3e [2] 3c 1c [2] 28 07 [2] 27 1d [2] 39 00 [2] 3b 01 [2] 20 07 [2] 3c 00 [2] 20 2f }

  condition:
    any of them
}