rule TTP_XOR_QUAD_CurrentVersionRun_2a73 {
  strings:
    $key_2a73 = { 79 1c [2] 5d 12 [2] 76 3e [2] 58 1c [2] 4c 07 [2] 43 1d [2] 5d 00 [2] 5f 01 [2] 44 07 [2] 58 00 [2] 44 2f }

  condition:
    any of them
}