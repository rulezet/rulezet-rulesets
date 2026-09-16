rule TTP_XOR_QUAD_CurrentVersionRun_1473 {
  strings:
    $key_1473 = { 47 1c [2] 63 12 [2] 48 3e [2] 66 1c [2] 72 07 [2] 7d 1d [2] 63 00 [2] 61 01 [2] 7a 07 [2] 66 00 [2] 7a 2f }

  condition:
    any of them
}