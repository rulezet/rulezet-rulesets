rule TTP_XOR_QUAD_CurrentVersionRun_2473 {
  strings:
    $key_2473 = { 77 1c [2] 53 12 [2] 78 3e [2] 56 1c [2] 42 07 [2] 4d 1d [2] 53 00 [2] 51 01 [2] 4a 07 [2] 56 00 [2] 4a 2f }

  condition:
    any of them
}