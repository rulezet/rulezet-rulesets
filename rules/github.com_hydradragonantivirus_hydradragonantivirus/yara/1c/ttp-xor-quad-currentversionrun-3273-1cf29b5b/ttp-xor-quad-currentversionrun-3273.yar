rule TTP_XOR_QUAD_CurrentVersionRun_3273 {
  strings:
    $key_3273 = { 61 1c [2] 45 12 [2] 6e 3e [2] 40 1c [2] 54 07 [2] 5b 1d [2] 45 00 [2] 47 01 [2] 5c 07 [2] 40 00 [2] 5c 2f }

  condition:
    any of them
}