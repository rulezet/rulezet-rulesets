rule TTP_XOR_QUAD_CurrentVersionRun_6273 {
  strings:
    $key_6273 = { 31 1c [2] 15 12 [2] 3e 3e [2] 10 1c [2] 04 07 [2] 0b 1d [2] 15 00 [2] 17 01 [2] 0c 07 [2] 10 00 [2] 0c 2f }

  condition:
    any of them
}