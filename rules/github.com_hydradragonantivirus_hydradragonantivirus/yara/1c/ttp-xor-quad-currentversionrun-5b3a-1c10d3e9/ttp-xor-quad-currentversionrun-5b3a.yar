rule TTP_XOR_QUAD_CurrentVersionRun_5b3a {
  strings:
    $key_5b3a = { 08 55 [2] 2c 5b [2] 07 77 [2] 29 55 [2] 3d 4e [2] 32 54 [2] 2c 49 [2] 2e 48 [2] 35 4e [2] 29 49 [2] 35 66 }

  condition:
    any of them
}