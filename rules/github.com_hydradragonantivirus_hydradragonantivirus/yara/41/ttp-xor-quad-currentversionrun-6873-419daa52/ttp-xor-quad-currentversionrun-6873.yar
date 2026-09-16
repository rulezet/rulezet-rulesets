rule TTP_XOR_QUAD_CurrentVersionRun_6873 {
  strings:
    $key_6873 = { 3b 1c [2] 1f 12 [2] 34 3e [2] 1a 1c [2] 0e 07 [2] 01 1d [2] 1f 00 [2] 1d 01 [2] 06 07 [2] 1a 00 [2] 06 2f }

  condition:
    any of them
}