rule TTP_XOR_QUAD_CurrentVersionRun_535d {
  strings:
    $key_535d = { 00 32 [2] 24 3c [2] 0f 10 [2] 21 32 [2] 35 29 [2] 3a 33 [2] 24 2e [2] 26 2f [2] 3d 29 [2] 21 2e [2] 3d 01 }

  condition:
    any of them
}