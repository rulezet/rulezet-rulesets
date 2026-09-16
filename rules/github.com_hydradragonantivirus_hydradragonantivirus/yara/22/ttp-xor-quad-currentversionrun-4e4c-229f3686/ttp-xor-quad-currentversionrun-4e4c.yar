rule TTP_XOR_QUAD_CurrentVersionRun_4e4c {
  strings:
    $key_4e4c = { 1d 23 [2] 39 2d [2] 12 01 [2] 3c 23 [2] 28 38 [2] 27 22 [2] 39 3f [2] 3b 3e [2] 20 38 [2] 3c 3f [2] 20 10 }

  condition:
    any of them
}