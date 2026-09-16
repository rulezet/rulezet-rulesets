rule TTP_XOR_QUAD_CurrentVersionRun_604c {
  strings:
    $key_604c = { 33 23 [2] 17 2d [2] 3c 01 [2] 12 23 [2] 06 38 [2] 09 22 [2] 17 3f [2] 15 3e [2] 0e 38 [2] 12 3f [2] 0e 10 }

  condition:
    any of them
}