rule TTP_XOR_QUAD_CurrentVersionRun_5b62 {
  strings:
    $key_5b62 = { 08 0d [2] 2c 03 [2] 07 2f [2] 29 0d [2] 3d 16 [2] 32 0c [2] 2c 11 [2] 2e 10 [2] 35 16 [2] 29 11 [2] 35 3e }

  condition:
    any of them
}