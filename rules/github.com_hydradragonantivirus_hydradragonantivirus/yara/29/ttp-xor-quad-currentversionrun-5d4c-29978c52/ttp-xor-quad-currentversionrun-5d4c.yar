rule TTP_XOR_QUAD_CurrentVersionRun_5d4c {
  strings:
    $key_5d4c = { 0e 23 [2] 2a 2d [2] 01 01 [2] 2f 23 [2] 3b 38 [2] 34 22 [2] 2a 3f [2] 28 3e [2] 33 38 [2] 2f 3f [2] 33 10 }

  condition:
    any of them
}