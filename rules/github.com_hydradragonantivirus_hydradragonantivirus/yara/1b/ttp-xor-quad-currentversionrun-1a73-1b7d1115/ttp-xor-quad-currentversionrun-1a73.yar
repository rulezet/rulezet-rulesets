rule TTP_XOR_QUAD_CurrentVersionRun_1a73 {
  strings:
    $key_1a73 = { 49 1c [2] 6d 12 [2] 46 3e [2] 68 1c [2] 7c 07 [2] 73 1d [2] 6d 00 [2] 6f 01 [2] 74 07 [2] 68 00 [2] 74 2f }

  condition:
    any of them
}