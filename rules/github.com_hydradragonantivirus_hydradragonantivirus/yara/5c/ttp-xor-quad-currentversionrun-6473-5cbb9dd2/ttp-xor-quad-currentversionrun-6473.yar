rule TTP_XOR_QUAD_CurrentVersionRun_6473 {
  strings:
    $key_6473 = { 37 1c [2] 13 12 [2] 38 3e [2] 16 1c [2] 02 07 [2] 0d 1d [2] 13 00 [2] 11 01 [2] 0a 07 [2] 16 00 [2] 0a 2f }

  condition:
    any of them
}