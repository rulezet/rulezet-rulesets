rule TTP_XOR_QUAD_CurrentVersionRun_684d {
  strings:
    $key_684d = { 3b 22 [2] 1f 2c [2] 34 00 [2] 1a 22 [2] 0e 39 [2] 01 23 [2] 1f 3e [2] 1d 3f [2] 06 39 [2] 1a 3e [2] 06 11 }

  condition:
    any of them
}