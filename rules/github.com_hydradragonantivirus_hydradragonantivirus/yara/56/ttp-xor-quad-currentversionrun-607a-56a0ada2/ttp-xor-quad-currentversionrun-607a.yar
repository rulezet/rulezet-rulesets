rule TTP_XOR_QUAD_CurrentVersionRun_607a {
  strings:
    $key_607a = { 33 15 [2] 17 1b [2] 3c 37 [2] 12 15 [2] 06 0e [2] 09 14 [2] 17 09 [2] 15 08 [2] 0e 0e [2] 12 09 [2] 0e 26 }

  condition:
    any of them
}