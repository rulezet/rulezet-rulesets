rule TTP_XOR_QUAD_CurrentVersionRun_4772 {
  strings:
    $key_4772 = { 14 1d [2] 30 13 [2] 1b 3f [2] 35 1d [2] 21 06 [2] 2e 1c [2] 30 01 [2] 32 00 [2] 29 06 [2] 35 01 [2] 29 2e }

  condition:
    any of them
}