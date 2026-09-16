rule TTP_XOR_QUAD_CurrentVersionRun_3473 {
  strings:
    $key_3473 = { 67 1c [2] 43 12 [2] 68 3e [2] 46 1c [2] 52 07 [2] 5d 1d [2] 43 00 [2] 41 01 [2] 5a 07 [2] 46 00 [2] 5a 2f }

  condition:
    any of them
}