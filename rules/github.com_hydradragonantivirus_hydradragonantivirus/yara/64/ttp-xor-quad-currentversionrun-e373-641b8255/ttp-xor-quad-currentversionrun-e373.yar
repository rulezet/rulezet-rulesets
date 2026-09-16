rule TTP_XOR_QUAD_CurrentVersionRun_e373 {
  strings:
    $key_e373 = { b0 1c [2] 94 12 [2] bf 3e [2] 91 1c [2] 85 07 [2] 8a 1d [2] 94 00 [2] 96 01 [2] 8d 07 [2] 91 00 [2] 8d 2f }

  condition:
    any of them
}