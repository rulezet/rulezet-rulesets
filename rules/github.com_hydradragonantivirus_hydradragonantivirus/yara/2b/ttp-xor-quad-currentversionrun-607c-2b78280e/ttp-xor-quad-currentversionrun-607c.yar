rule TTP_XOR_QUAD_CurrentVersionRun_607c {
  strings:
    $key_607c = { 33 13 [2] 17 1d [2] 3c 31 [2] 12 13 [2] 06 08 [2] 09 12 [2] 17 0f [2] 15 0e [2] 0e 08 [2] 12 0f [2] 0e 20 }

  condition:
    any of them
}