rule TTP_XOR_QUAD_CurrentVersionRun_6372 {
  strings:
    $key_6372 = { 30 1d [2] 14 13 [2] 3f 3f [2] 11 1d [2] 05 06 [2] 0a 1c [2] 14 01 [2] 16 00 [2] 0d 06 [2] 11 01 [2] 0d 2e }

  condition:
    any of them
}