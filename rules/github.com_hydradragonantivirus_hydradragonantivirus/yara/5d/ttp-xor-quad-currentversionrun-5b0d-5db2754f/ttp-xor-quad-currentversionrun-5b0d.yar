rule TTP_XOR_QUAD_CurrentVersionRun_5b0d {
  strings:
    $key_5b0d = { 08 62 [2] 2c 6c [2] 07 40 [2] 29 62 [2] 3d 79 [2] 32 63 [2] 2c 7e [2] 2e 7f [2] 35 79 [2] 29 7e [2] 35 51 }

  condition:
    any of them
}