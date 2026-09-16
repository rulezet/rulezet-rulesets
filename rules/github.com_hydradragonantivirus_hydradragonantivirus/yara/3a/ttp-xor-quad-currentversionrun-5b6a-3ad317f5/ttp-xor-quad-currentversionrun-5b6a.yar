rule TTP_XOR_QUAD_CurrentVersionRun_5b6a {
  strings:
    $key_5b6a = { 08 05 [2] 2c 0b [2] 07 27 [2] 29 05 [2] 3d 1e [2] 32 04 [2] 2c 19 [2] 2e 18 [2] 35 1e [2] 29 19 [2] 35 36 }

  condition:
    any of them
}