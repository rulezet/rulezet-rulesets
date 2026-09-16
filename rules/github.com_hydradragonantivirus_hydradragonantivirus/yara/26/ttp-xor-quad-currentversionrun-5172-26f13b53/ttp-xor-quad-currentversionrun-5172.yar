rule TTP_XOR_QUAD_CurrentVersionRun_5172 {
  strings:
    $key_5172 = { 02 1d [2] 26 13 [2] 0d 3f [2] 23 1d [2] 37 06 [2] 38 1c [2] 26 01 [2] 24 00 [2] 3f 06 [2] 23 01 [2] 3f 2e }

  condition:
    any of them
}