rule TTP_XOR_QUAD_CurrentVersionRun_744d {
  strings:
    $key_744d = { 27 22 [2] 03 2c [2] 28 00 [2] 06 22 [2] 12 39 [2] 1d 23 [2] 03 3e [2] 01 3f [2] 1a 39 [2] 06 3e [2] 1a 11 }

  condition:
    any of them
}