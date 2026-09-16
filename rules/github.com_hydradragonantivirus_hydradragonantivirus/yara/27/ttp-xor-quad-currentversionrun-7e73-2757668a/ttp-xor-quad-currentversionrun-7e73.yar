rule TTP_XOR_QUAD_CurrentVersionRun_7e73 {
  strings:
    $key_7e73 = { 2d 1c [2] 09 12 [2] 22 3e [2] 0c 1c [2] 18 07 [2] 17 1d [2] 09 00 [2] 0b 01 [2] 10 07 [2] 0c 00 [2] 10 2f }

  condition:
    any of them
}