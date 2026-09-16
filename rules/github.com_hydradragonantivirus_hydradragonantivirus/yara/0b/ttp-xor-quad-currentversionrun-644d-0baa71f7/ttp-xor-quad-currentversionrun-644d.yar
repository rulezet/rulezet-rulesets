rule TTP_XOR_QUAD_CurrentVersionRun_644d {
  strings:
    $key_644d = { 37 22 [2] 13 2c [2] 38 00 [2] 16 22 [2] 02 39 [2] 0d 23 [2] 13 3e [2] 11 3f [2] 0a 39 [2] 16 3e [2] 0a 11 }

  condition:
    any of them
}