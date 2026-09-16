rule TTP_XOR_QUAD_CurrentVersionRun_5a2c {
  strings:
    $key_5a2c = { 09 43 [2] 2d 4d [2] 06 61 [2] 28 43 [2] 3c 58 [2] 33 42 [2] 2d 5f [2] 2f 5e [2] 34 58 [2] 28 5f [2] 34 70 }

  condition:
    any of them
}