rule TTP_XOR_QUAD_CurrentVersionRun_634d {
  strings:
    $key_634d = { 30 22 [2] 14 2c [2] 3f 00 [2] 11 22 [2] 05 39 [2] 0a 23 [2] 14 3e [2] 16 3f [2] 0d 39 [2] 11 3e [2] 0d 11 }

  condition:
    any of them
}