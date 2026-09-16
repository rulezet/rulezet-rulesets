rule TTP_XOR_QUAD_CurrentVersionRun_7573 {
  strings:
    $key_7573 = { 26 1c [2] 02 12 [2] 29 3e [2] 07 1c [2] 13 07 [2] 1c 1d [2] 02 00 [2] 00 01 [2] 1b 07 [2] 07 00 [2] 1b 2f }

  condition:
    any of them
}