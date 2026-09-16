rule TTP_XOR_QUAD_CurrentVersionRun_75ed {
  strings:
    $key_75ed = { 26 82 [2] 02 8c [2] 29 a0 [2] 07 82 [2] 13 99 [2] 1c 83 [2] 02 9e [2] 00 9f [2] 1b 99 [2] 07 9e [2] 1b b1 }

  condition:
    any of them
}