rule TTP_XOR_QUAD_CurrentVersionRun_72ed {
  strings:
    $key_72ed = { 21 82 [2] 05 8c [2] 2e a0 [2] 00 82 [2] 14 99 [2] 1b 83 [2] 05 9e [2] 07 9f [2] 1c 99 [2] 00 9e [2] 1c b1 }

  condition:
    any of them
}