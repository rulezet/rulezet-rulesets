rule TTP_XOR_QUAD_CurrentVersionRun_5bea {
  strings:
    $key_5bea = { 08 85 [2] 2c 8b [2] 07 a7 [2] 29 85 [2] 3d 9e [2] 32 84 [2] 2c 99 [2] 2e 98 [2] 35 9e [2] 29 99 [2] 35 b6 }

  condition:
    any of them
}