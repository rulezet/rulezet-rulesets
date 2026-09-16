rule TTP_XOR_QUAD_CurrentVersionRun_5250 {
  strings:
    $key_5250 = { 01 3f [2] 25 31 [2] 0e 1d [2] 20 3f [2] 34 24 [2] 3b 3e [2] 25 23 [2] 27 22 [2] 3c 24 [2] 20 23 [2] 3c 0c }

  condition:
    any of them
}