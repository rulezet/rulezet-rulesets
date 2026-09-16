rule TTP_XOR_QUAD_CurrentVersionRun_1f5c {
  strings:
    $key_1f5c = { 4c 33 [2] 68 3d [2] 43 11 [2] 6d 33 [2] 79 28 [2] 76 32 [2] 68 2f [2] 6a 2e [2] 71 28 [2] 6d 2f [2] 71 00 }

  condition:
    any of them
}