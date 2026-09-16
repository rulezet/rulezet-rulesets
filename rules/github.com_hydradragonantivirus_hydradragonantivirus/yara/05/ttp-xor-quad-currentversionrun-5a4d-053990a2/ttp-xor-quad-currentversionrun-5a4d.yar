rule TTP_XOR_QUAD_CurrentVersionRun_5a4d {
  strings:
    $key_5a4d = { 09 22 [2] 2d 2c [2] 06 00 [2] 28 22 [2] 3c 39 [2] 33 23 [2] 2d 3e [2] 2f 3f [2] 34 39 [2] 28 3e [2] 34 11 }

  condition:
    any of them
}