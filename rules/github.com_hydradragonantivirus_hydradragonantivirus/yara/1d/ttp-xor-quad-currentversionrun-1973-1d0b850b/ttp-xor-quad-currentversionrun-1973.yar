rule TTP_XOR_QUAD_CurrentVersionRun_1973 {
  strings:
    $key_1973 = { 4a 1c [2] 6e 12 [2] 45 3e [2] 6b 1c [2] 7f 07 [2] 70 1d [2] 6e 00 [2] 6c 01 [2] 77 07 [2] 6b 00 [2] 77 2f }

  condition:
    any of them
}