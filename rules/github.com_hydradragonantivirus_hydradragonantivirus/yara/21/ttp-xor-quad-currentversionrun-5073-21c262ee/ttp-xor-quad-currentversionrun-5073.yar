rule TTP_XOR_QUAD_CurrentVersionRun_5073 {
  strings:
    $key_5073 = { 03 1c [2] 27 12 [2] 0c 3e [2] 22 1c [2] 36 07 [2] 39 1d [2] 27 00 [2] 25 01 [2] 3e 07 [2] 22 00 [2] 3e 2f }

  condition:
    any of them
}