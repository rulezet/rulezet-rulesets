rule TTP_XOR_QUAD_CurrentVersionRun_5a72 {
  strings:
    $key_5a72 = { 09 1d [2] 2d 13 [2] 06 3f [2] 28 1d [2] 3c 06 [2] 33 1c [2] 2d 01 [2] 2f 00 [2] 34 06 [2] 28 01 [2] 34 2e }

  condition:
    any of them
}