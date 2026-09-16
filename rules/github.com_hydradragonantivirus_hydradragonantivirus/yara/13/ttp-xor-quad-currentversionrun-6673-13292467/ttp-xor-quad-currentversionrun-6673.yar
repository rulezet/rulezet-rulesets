rule TTP_XOR_QUAD_CurrentVersionRun_6673 {
  strings:
    $key_6673 = { 35 1c [2] 11 12 [2] 3a 3e [2] 14 1c [2] 00 07 [2] 0f 1d [2] 11 00 [2] 13 01 [2] 08 07 [2] 14 00 [2] 08 2f }

  condition:
    any of them
}