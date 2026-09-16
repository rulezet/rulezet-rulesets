rule TTP_XOR_QUAD_CurrentVersionRun_1572 {
  strings:
    $key_1572 = { 46 1d [2] 62 13 [2] 49 3f [2] 67 1d [2] 73 06 [2] 7c 1c [2] 62 01 [2] 60 00 [2] 7b 06 [2] 67 01 [2] 7b 2e }

  condition:
    any of them
}