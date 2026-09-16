rule TTP_XOR_QUAD_CurrentVersionRun_1f73 {
  strings:
    $key_1f73 = { 4c 1c [2] 68 12 [2] 43 3e [2] 6d 1c [2] 79 07 [2] 76 1d [2] 68 00 [2] 6a 01 [2] 71 07 [2] 6d 00 [2] 71 2f }

  condition:
    any of them
}