rule TTP_XOR_QUAD_CurrentVersionRun_5b2c {
  strings:
    $key_5b2c = { 08 43 [2] 2c 4d [2] 07 61 [2] 29 43 [2] 3d 58 [2] 32 42 [2] 2c 5f [2] 2e 5e [2] 35 58 [2] 29 5f [2] 35 70 }

  condition:
    any of them
}