rule TTP_XOR_QUAD_CurrentVersionRun_3673 {
  strings:
    $key_3673 = { 65 1c [2] 41 12 [2] 6a 3e [2] 44 1c [2] 50 07 [2] 5f 1d [2] 41 00 [2] 43 01 [2] 58 07 [2] 44 00 [2] 58 2f }

  condition:
    any of them
}