rule TTP_XOR_QUAD_CurrentVersionRun_4f2c {
  strings:
    $key_4f2c = { 1c 43 [2] 38 4d [2] 13 61 [2] 3d 43 [2] 29 58 [2] 26 42 [2] 38 5f [2] 3a 5e [2] 21 58 [2] 3d 5f [2] 21 70 }

  condition:
    any of them
}