rule TTP_XOR_QUAD_CurrentVersionRun_5f5d {
  strings:
    $key_5f5d = { 0c 32 [2] 28 3c [2] 03 10 [2] 2d 32 [2] 39 29 [2] 36 33 [2] 28 2e [2] 2a 2f [2] 31 29 [2] 2d 2e [2] 31 01 }

  condition:
    any of them
}