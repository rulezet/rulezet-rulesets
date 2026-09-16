rule TTP_XOR_QUAD_CurrentVersionRun_5b4a {
  strings:
    $key_5b4a = { 08 25 [2] 2c 2b [2] 07 07 [2] 29 25 [2] 3d 3e [2] 32 24 [2] 2c 39 [2] 2e 38 [2] 35 3e [2] 29 39 [2] 35 16 }

  condition:
    any of them
}