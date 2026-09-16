rule TTP_XOR_QUAD_CurrentVersionRun_60ed {
  strings:
    $key_60ed = { 33 82 [2] 17 8c [2] 3c a0 [2] 12 82 [2] 06 99 [2] 09 83 [2] 17 9e [2] 15 9f [2] 0e 99 [2] 12 9e [2] 0e b1 }

  condition:
    any of them
}