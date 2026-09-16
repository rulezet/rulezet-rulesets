rule TTP_XOR_QUAD_CurrentVersionRun_f273 {
  strings:
    $key_f273 = { a1 1c [2] 85 12 [2] ae 3e [2] 80 1c [2] 94 07 [2] 9b 1d [2] 85 00 [2] 87 01 [2] 9c 07 [2] 80 00 [2] 9c 2f }

  condition:
    any of them
}