rule TTP_XOR_QUAD_CurrentVersionRun_5b02 {
  strings:
    $key_5b02 = { 08 6d [2] 2c 63 [2] 07 4f [2] 29 6d [2] 3d 76 [2] 32 6c [2] 2c 71 [2] 2e 70 [2] 35 76 [2] 29 71 [2] 35 5e }

  condition:
    any of them
}