rule TTP_XOR_QUAD_CurrentVersionRun_7c4c {
  strings:
    $key_7c4c = { 2f 23 [2] 0b 2d [2] 20 01 [2] 0e 23 [2] 1a 38 [2] 15 22 [2] 0b 3f [2] 09 3e [2] 12 38 [2] 0e 3f [2] 12 10 }

  condition:
    any of them
}