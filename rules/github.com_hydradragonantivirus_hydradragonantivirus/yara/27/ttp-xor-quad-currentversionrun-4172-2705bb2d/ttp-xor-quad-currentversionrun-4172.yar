rule TTP_XOR_QUAD_CurrentVersionRun_4172 {
  strings:
    $key_4172 = { 12 1d [2] 36 13 [2] 1d 3f [2] 33 1d [2] 27 06 [2] 28 1c [2] 36 01 [2] 34 00 [2] 2f 06 [2] 33 01 [2] 2f 2e }

  condition:
    any of them
}