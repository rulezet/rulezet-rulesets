rule TTP_XOR_QUAD_CurrentVersionRun_644c {
  strings:
    $key_644c = { 37 23 [2] 13 2d [2] 38 01 [2] 16 23 [2] 02 38 [2] 0d 22 [2] 13 3f [2] 11 3e [2] 0a 38 [2] 16 3f [2] 0a 10 }

  condition:
    any of them
}