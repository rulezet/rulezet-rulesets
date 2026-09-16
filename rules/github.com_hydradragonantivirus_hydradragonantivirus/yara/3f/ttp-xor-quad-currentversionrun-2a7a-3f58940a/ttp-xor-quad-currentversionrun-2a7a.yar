rule TTP_XOR_QUAD_CurrentVersionRun_2a7a {
  strings:
    $key_2a7a = { 79 15 [2] 5d 1b [2] 76 37 [2] 58 15 [2] 4c 0e [2] 43 14 [2] 5d 09 [2] 5f 08 [2] 44 0e [2] 58 09 [2] 44 26 }

  condition:
    any of them
}