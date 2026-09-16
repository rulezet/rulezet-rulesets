rule TTP_XOR_QUAD_CurrentVersionRun_5d4d {
  strings:
    $key_5d4d = { 0e 22 [2] 2a 2c [2] 01 00 [2] 2f 22 [2] 3b 39 [2] 34 23 [2] 2a 3e [2] 28 3f [2] 33 39 [2] 2f 3e [2] 33 11 }

  condition:
    any of them
}