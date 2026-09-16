rule TTP_XOR_QUAD_CurrentVersionRun_60ec {
  strings:
    $key_60ec = { 33 83 [2] 17 8d [2] 3c a1 [2] 12 83 [2] 06 98 [2] 09 82 [2] 17 9f [2] 15 9e [2] 0e 98 [2] 12 9f [2] 0e b0 }

  condition:
    any of them
}