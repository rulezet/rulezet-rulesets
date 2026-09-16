rule TTP_XOR_QUAD_CurrentVersionRun_2873 {
  strings:
    $key_2873 = { 7b 1c [2] 5f 12 [2] 74 3e [2] 5a 1c [2] 4e 07 [2] 41 1d [2] 5f 00 [2] 5d 01 [2] 46 07 [2] 5a 00 [2] 46 2f }

  condition:
    any of them
}