rule TTP_XOR_QUAD_CurrentVersionRun_4b5c {
  strings:
    $key_4b5c = { 18 33 [2] 3c 3d [2] 17 11 [2] 39 33 [2] 2d 28 [2] 22 32 [2] 3c 2f [2] 3e 2e [2] 25 28 [2] 39 2f [2] 25 00 }

  condition:
    any of them
}