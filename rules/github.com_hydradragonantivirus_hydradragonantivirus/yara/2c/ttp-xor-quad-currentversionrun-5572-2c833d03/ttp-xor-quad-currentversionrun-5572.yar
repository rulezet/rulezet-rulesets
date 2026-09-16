rule TTP_XOR_QUAD_CurrentVersionRun_5572 {
  strings:
    $key_5572 = { 06 1d [2] 22 13 [2] 09 3f [2] 27 1d [2] 33 06 [2] 3c 1c [2] 22 01 [2] 20 00 [2] 3b 06 [2] 27 01 [2] 3b 2e }

  condition:
    any of them
}