rule TTP_XOR_QUAD_CurrentVersionRun_7c72 {
  strings:
    $key_7c72 = { 2f 1d [2] 0b 13 [2] 20 3f [2] 0e 1d [2] 1a 06 [2] 15 1c [2] 0b 01 [2] 09 00 [2] 12 06 [2] 0e 01 [2] 12 2e }

  condition:
    any of them
}