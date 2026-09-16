rule TTP_XOR_QUAD_CurrentVersionRun_7372 {
  strings:
    $key_7372 = { 20 1d [2] 04 13 [2] 2f 3f [2] 01 1d [2] 15 06 [2] 1a 1c [2] 04 01 [2] 06 00 [2] 1d 06 [2] 01 01 [2] 1d 2e }

  condition:
    any of them
}