rule TTP_XOR_QUAD_CurrentVersionRun_5f73 {
  strings:
    $key_5f73 = { 0c 1c [2] 28 12 [2] 03 3e [2] 2d 1c [2] 39 07 [2] 36 1d [2] 28 00 [2] 2a 01 [2] 31 07 [2] 2d 00 [2] 31 2f }

  condition:
    any of them
}