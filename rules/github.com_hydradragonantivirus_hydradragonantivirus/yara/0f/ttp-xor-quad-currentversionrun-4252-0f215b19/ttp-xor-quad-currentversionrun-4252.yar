rule TTP_XOR_QUAD_CurrentVersionRun_4252 {
  strings:
    $key_4252 = { 11 3d [2] 35 33 [2] 1e 1f [2] 30 3d [2] 24 26 [2] 2b 3c [2] 35 21 [2] 37 20 [2] 2c 26 [2] 30 21 [2] 2c 0e }

  condition:
    any of them
}