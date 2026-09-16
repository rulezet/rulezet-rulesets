rule TTP_XOR_QUAD_CurrentVersionRun_70ed {
  strings:
    $key_70ed = { 23 82 [2] 07 8c [2] 2c a0 [2] 02 82 [2] 16 99 [2] 19 83 [2] 07 9e [2] 05 9f [2] 1e 99 [2] 02 9e [2] 1e b1 }

  condition:
    any of them
}