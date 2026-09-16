rule TTP_XOR_QUAD_CurrentVersionRun_4f5d {
  strings:
    $key_4f5d = { 1c 32 [2] 38 3c [2] 13 10 [2] 3d 32 [2] 29 29 [2] 26 33 [2] 38 2e [2] 3a 2f [2] 21 29 [2] 3d 2e [2] 21 01 }

  condition:
    any of them
}