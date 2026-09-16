rule TTP_XOR_QUAD_CurrentVersionRun_60ef {
  strings:
    $key_60ef = { 33 80 [2] 17 8e [2] 3c a2 [2] 12 80 [2] 06 9b [2] 09 81 [2] 17 9c [2] 15 9d [2] 0e 9b [2] 12 9c [2] 0e b3 }

  condition:
    any of them
}