rule TTP_XOR_QUAD_CurrentVersionRun_7b4c {
  strings:
    $key_7b4c = { 28 23 [2] 0c 2d [2] 27 01 [2] 09 23 [2] 1d 38 [2] 12 22 [2] 0c 3f [2] 0e 3e [2] 15 38 [2] 09 3f [2] 15 10 }

  condition:
    any of them
}