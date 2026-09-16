rule TTP_XOR_QUAD_CurrentVersionRun_6f4c {
  strings:
    $key_6f4c = { 3c 23 [2] 18 2d [2] 33 01 [2] 1d 23 [2] 09 38 [2] 06 22 [2] 18 3f [2] 1a 3e [2] 01 38 [2] 1d 3f [2] 01 10 }

  condition:
    any of them
}