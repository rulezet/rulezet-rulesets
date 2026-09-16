rule TTP_XOR_QUAD_CurrentVersionRun_7a73 {
  strings:
    $key_7a73 = { 29 1c [2] 0d 12 [2] 26 3e [2] 08 1c [2] 1c 07 [2] 13 1d [2] 0d 00 [2] 0f 01 [2] 14 07 [2] 08 00 [2] 14 2f }

  condition:
    any of them
}