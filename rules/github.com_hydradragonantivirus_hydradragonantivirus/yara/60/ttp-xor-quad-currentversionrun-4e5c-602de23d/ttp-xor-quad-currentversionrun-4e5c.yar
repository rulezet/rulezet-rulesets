rule TTP_XOR_QUAD_CurrentVersionRun_4e5c {
  strings:
    $key_4e5c = { 1d 33 [2] 39 3d [2] 12 11 [2] 3c 33 [2] 28 28 [2] 27 32 [2] 39 2f [2] 3b 2e [2] 20 28 [2] 3c 2f [2] 20 00 }

  condition:
    any of them
}