rule TTP_XOR_QUAD_CurrentVersionRun_0573 {
  strings:
    $key_0573 = { 56 1c [2] 72 12 [2] 59 3e [2] 77 1c [2] 63 07 [2] 6c 1d [2] 72 00 [2] 70 01 [2] 6b 07 [2] 77 00 [2] 6b 2f }

  condition:
    any of them
}