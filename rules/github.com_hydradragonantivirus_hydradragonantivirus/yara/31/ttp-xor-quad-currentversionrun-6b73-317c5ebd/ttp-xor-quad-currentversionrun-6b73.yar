rule TTP_XOR_QUAD_CurrentVersionRun_6b73 {
  strings:
    $key_6b73 = { 38 1c [2] 1c 12 [2] 37 3e [2] 19 1c [2] 0d 07 [2] 02 1d [2] 1c 00 [2] 1e 01 [2] 05 07 [2] 19 00 [2] 05 2f }

  condition:
    any of them
}