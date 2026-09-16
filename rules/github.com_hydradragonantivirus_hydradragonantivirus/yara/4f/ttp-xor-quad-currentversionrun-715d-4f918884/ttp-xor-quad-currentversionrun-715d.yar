rule TTP_XOR_QUAD_CurrentVersionRun_715d {
  strings:
    $key_715d = { 22 32 [2] 06 3c [2] 2d 10 [2] 03 32 [2] 17 29 [2] 18 33 [2] 06 2e [2] 04 2f [2] 1f 29 [2] 03 2e [2] 1f 01 }

  condition:
    any of them
}