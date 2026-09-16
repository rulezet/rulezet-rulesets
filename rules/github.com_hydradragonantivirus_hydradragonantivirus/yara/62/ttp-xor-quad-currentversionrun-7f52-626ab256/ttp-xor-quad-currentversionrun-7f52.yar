rule TTP_XOR_QUAD_CurrentVersionRun_7f52 {
  strings:
    $key_7f52 = { 2c 3d [2] 08 33 [2] 23 1f [2] 0d 3d [2] 19 26 [2] 16 3c [2] 08 21 [2] 0a 20 [2] 11 26 [2] 0d 21 [2] 11 0e }

  condition:
    any of them
}