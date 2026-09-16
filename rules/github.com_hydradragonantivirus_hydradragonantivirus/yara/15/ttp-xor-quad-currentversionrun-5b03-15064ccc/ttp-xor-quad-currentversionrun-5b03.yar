rule TTP_XOR_QUAD_CurrentVersionRun_5b03 {
  strings:
    $key_5b03 = { 08 6c [2] 2c 62 [2] 07 4e [2] 29 6c [2] 3d 77 [2] 32 6d [2] 2c 70 [2] 2e 71 [2] 35 77 [2] 29 70 [2] 35 5f }

  condition:
    any of them
}