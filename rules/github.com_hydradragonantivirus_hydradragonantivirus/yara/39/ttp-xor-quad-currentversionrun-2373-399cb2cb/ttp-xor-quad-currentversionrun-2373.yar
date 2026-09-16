rule TTP_XOR_QUAD_CurrentVersionRun_2373 {
  strings:
    $key_2373 = { 70 1c [2] 54 12 [2] 7f 3e [2] 51 1c [2] 45 07 [2] 4a 1d [2] 54 00 [2] 56 01 [2] 4d 07 [2] 51 00 [2] 4d 2f }

  condition:
    any of them
}