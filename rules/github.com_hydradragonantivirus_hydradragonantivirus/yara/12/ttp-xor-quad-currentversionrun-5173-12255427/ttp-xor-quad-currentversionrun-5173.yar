rule TTP_XOR_QUAD_CurrentVersionRun_5173 {
  strings:
    $key_5173 = { 02 1c [2] 26 12 [2] 0d 3e [2] 23 1c [2] 37 07 [2] 38 1d [2] 26 00 [2] 24 01 [2] 3f 07 [2] 23 00 [2] 3f 2f }

  condition:
    any of them
}