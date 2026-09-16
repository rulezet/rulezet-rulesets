rule TTP_XOR_QUAD_CurrentVersionRun_6a73 {
  strings:
    $key_6a73 = { 39 1c [2] 1d 12 [2] 36 3e [2] 18 1c [2] 0c 07 [2] 03 1d [2] 1d 00 [2] 1f 01 [2] 04 07 [2] 18 00 [2] 04 2f }

  condition:
    any of them
}