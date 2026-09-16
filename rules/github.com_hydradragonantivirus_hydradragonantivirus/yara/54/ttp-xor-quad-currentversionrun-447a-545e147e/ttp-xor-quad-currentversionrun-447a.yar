rule TTP_XOR_QUAD_CurrentVersionRun_447a {
  strings:
    $key_447a = { 17 15 [2] 33 1b [2] 18 37 [2] 36 15 [2] 22 0e [2] 2d 14 [2] 33 09 [2] 31 08 [2] 2a 0e [2] 36 09 [2] 2a 26 }

  condition:
    any of them
}