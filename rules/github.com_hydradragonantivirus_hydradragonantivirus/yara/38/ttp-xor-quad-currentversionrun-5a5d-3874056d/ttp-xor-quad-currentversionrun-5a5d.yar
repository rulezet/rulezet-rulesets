rule TTP_XOR_QUAD_CurrentVersionRun_5a5d {
  strings:
    $key_5a5d = { 09 32 [2] 2d 3c [2] 06 10 [2] 28 32 [2] 3c 29 [2] 33 33 [2] 2d 2e [2] 2f 2f [2] 34 29 [2] 28 2e [2] 34 01 }

  condition:
    any of them
}