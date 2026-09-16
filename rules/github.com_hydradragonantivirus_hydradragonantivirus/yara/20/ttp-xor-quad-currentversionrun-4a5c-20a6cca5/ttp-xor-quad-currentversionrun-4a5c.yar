rule TTP_XOR_QUAD_CurrentVersionRun_4a5c {
  strings:
    $key_4a5c = { 19 33 [2] 3d 3d [2] 16 11 [2] 38 33 [2] 2c 28 [2] 23 32 [2] 3d 2f [2] 3f 2e [2] 24 28 [2] 38 2f [2] 24 00 }

  condition:
    any of them
}