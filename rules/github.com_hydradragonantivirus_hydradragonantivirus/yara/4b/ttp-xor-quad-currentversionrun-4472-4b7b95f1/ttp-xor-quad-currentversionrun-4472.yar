rule TTP_XOR_QUAD_CurrentVersionRun_4472 {
  strings:
    $key_4472 = { 17 1d [2] 33 13 [2] 18 3f [2] 36 1d [2] 22 06 [2] 2d 1c [2] 33 01 [2] 31 00 [2] 2a 06 [2] 36 01 [2] 2a 2e }

  condition:
    any of them
}