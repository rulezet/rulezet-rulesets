rule TTP_XOR_QUAD_CurrentVersionRun_2a7c {
  strings:
    $key_2a7c = { 79 13 [2] 5d 1d [2] 76 31 [2] 58 13 [2] 4c 08 [2] 43 12 [2] 5d 0f [2] 5f 0e [2] 44 08 [2] 58 0f [2] 44 20 }

  condition:
    any of them
}