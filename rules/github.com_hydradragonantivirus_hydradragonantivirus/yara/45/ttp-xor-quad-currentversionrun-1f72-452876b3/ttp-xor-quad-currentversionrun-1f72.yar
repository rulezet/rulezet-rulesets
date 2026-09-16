rule TTP_XOR_QUAD_CurrentVersionRun_1f72 {
  strings:
    $key_1f72 = { 4c 1d [2] 68 13 [2] 43 3f [2] 6d 1d [2] 79 06 [2] 76 1c [2] 68 01 [2] 6a 00 [2] 71 06 [2] 6d 01 [2] 71 2e }

  condition:
    any of them
}