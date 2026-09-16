rule TTP_XOR_QUAD_CurrentVersionRun_527a {
  strings:
    $key_527a = { 01 15 [2] 25 1b [2] 0e 37 [2] 20 15 [2] 34 0e [2] 3b 14 [2] 25 09 [2] 27 08 [2] 3c 0e [2] 20 09 [2] 3c 26 }

  condition:
    any of them
}