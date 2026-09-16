rule TTP_XOR_QUAD_CurrentVersionRun_3b73 {
  strings:
    $key_3b73 = { 68 1c [2] 4c 12 [2] 67 3e [2] 49 1c [2] 5d 07 [2] 52 1d [2] 4c 00 [2] 4e 01 [2] 55 07 [2] 49 00 [2] 55 2f }

  condition:
    any of them
}