rule TTP_XOR_QUAD_CurrentVersionRun_7972 {
  strings:
    $key_7972 = { 2a 1d [2] 0e 13 [2] 25 3f [2] 0b 1d [2] 1f 06 [2] 10 1c [2] 0e 01 [2] 0c 00 [2] 17 06 [2] 0b 01 [2] 17 2e }

  condition:
    any of them
}