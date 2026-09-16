rule TTP_XOR_QUAD_CurrentVersionRun_0273 {
  strings:
    $key_0273 = { 51 1c [2] 75 12 [2] 5e 3e [2] 70 1c [2] 64 07 [2] 6b 1d [2] 75 00 [2] 77 01 [2] 6c 07 [2] 70 00 [2] 6c 2f }

  condition:
    any of them
}