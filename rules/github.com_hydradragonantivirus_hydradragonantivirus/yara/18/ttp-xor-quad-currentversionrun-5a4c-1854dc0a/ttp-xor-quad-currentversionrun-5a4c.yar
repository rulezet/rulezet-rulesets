rule TTP_XOR_QUAD_CurrentVersionRun_5a4c {
  strings:
    $key_5a4c = { 09 23 [2] 2d 2d [2] 06 01 [2] 28 23 [2] 3c 38 [2] 33 22 [2] 2d 3f [2] 2f 3e [2] 34 38 [2] 28 3f [2] 34 10 }

  condition:
    any of them
}