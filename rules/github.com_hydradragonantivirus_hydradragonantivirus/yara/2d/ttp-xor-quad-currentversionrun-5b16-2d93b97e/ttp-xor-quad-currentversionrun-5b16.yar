rule TTP_XOR_QUAD_CurrentVersionRun_5b16 {
  strings:
    $key_5b16 = { 08 79 [2] 2c 77 [2] 07 5b [2] 29 79 [2] 3d 62 [2] 32 78 [2] 2c 65 [2] 2e 64 [2] 35 62 [2] 29 65 [2] 35 4a }

  condition:
    any of them
}