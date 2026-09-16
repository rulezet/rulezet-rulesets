rule TTP_XOR_QUAD_CurrentVersionRun_6072 {
  strings:
    $key_6072 = { 33 1d [2] 17 13 [2] 3c 3f [2] 12 1d [2] 06 06 [2] 09 1c [2] 17 01 [2] 15 00 [2] 0e 06 [2] 12 01 [2] 0e 2e }

  condition:
    any of them
}