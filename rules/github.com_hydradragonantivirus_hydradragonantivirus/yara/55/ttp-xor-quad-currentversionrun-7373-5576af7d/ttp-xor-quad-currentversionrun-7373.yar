rule TTP_XOR_QUAD_CurrentVersionRun_7373 {
  strings:
    $key_7373 = { 20 1c [2] 04 12 [2] 2f 3e [2] 01 1c [2] 15 07 [2] 1a 1d [2] 04 00 [2] 06 01 [2] 1d 07 [2] 01 00 [2] 1d 2f }

  condition:
    any of them
}