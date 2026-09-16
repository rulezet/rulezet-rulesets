rule TTP_XOR_QUAD_CurrentVersionRun_714d {
  strings:
    $key_714d = { 22 22 [2] 06 2c [2] 2d 00 [2] 03 22 [2] 17 39 [2] 18 23 [2] 06 3e [2] 04 3f [2] 1f 39 [2] 03 3e [2] 1f 11 }

  condition:
    any of them
}