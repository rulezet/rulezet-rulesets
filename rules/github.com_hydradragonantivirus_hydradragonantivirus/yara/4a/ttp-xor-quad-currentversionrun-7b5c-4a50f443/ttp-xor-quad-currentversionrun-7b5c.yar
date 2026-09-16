rule TTP_XOR_QUAD_CurrentVersionRun_7b5c {
  strings:
    $key_7b5c = { 28 33 [2] 0c 3d [2] 27 11 [2] 09 33 [2] 1d 28 [2] 12 32 [2] 0c 2f [2] 0e 2e [2] 15 28 [2] 09 2f [2] 15 00 }

  condition:
    any of them
}