rule TTP_XOR_QUAD_CurrentVersionRun_5773 {
  strings:
    $key_5773 = { 04 1c [2] 20 12 [2] 0b 3e [2] 25 1c [2] 31 07 [2] 3e 1d [2] 20 00 [2] 22 01 [2] 39 07 [2] 25 00 [2] 39 2f }

  condition:
    any of them
}