rule TTP_XOR_QUAD_CurrentVersionRun_4e4d {
  strings:
    $key_4e4d = { 1d 22 [2] 39 2c [2] 12 00 [2] 3c 22 [2] 28 39 [2] 27 23 [2] 39 3e [2] 3b 3f [2] 20 39 [2] 3c 3e [2] 20 11 }

  condition:
    any of them
}