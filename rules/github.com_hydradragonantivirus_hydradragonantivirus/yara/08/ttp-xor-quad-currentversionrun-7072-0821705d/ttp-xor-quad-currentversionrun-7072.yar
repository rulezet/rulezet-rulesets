rule TTP_XOR_QUAD_CurrentVersionRun_7072 {
  strings:
    $key_7072 = { 23 1d [2] 07 13 [2] 2c 3f [2] 02 1d [2] 16 06 [2] 19 1c [2] 07 01 [2] 05 00 [2] 1e 06 [2] 02 01 [2] 1e 2e }

  condition:
    any of them
}