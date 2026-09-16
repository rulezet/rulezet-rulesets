rule TTP_XOR_QUAD_CurrentVersionRun_5f72 {
  strings:
    $key_5f72 = { 0c 1d [2] 28 13 [2] 03 3f [2] 2d 1d [2] 39 06 [2] 36 1c [2] 28 01 [2] 2a 00 [2] 31 06 [2] 2d 01 [2] 31 2e }

  condition:
    any of them
}