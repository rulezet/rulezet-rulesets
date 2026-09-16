rule TTP_XOR_QUAD_CurrentVersionRun_2673 {
  strings:
    $key_2673 = { 75 1c [2] 51 12 [2] 7a 3e [2] 54 1c [2] 40 07 [2] 4f 1d [2] 51 00 [2] 53 01 [2] 48 07 [2] 54 00 [2] 48 2f }

  condition:
    any of them
}