rule TTP_XOR_QUAD_CurrentVersionRun_7572 {
  strings:
    $key_7572 = { 26 1d [2] 02 13 [2] 29 3f [2] 07 1d [2] 13 06 [2] 1c 1c [2] 02 01 [2] 00 00 [2] 1b 06 [2] 07 01 [2] 1b 2e }

  condition:
    any of them
}