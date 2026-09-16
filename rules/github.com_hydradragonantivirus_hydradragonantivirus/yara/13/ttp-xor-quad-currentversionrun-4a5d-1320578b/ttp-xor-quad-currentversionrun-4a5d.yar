rule TTP_XOR_QUAD_CurrentVersionRun_4a5d {
  strings:
    $key_4a5d = { 19 32 [2] 3d 3c [2] 16 10 [2] 38 32 [2] 2c 29 [2] 23 33 [2] 3d 2e [2] 3f 2f [2] 24 29 [2] 38 2e [2] 24 01 }

  condition:
    any of them
}