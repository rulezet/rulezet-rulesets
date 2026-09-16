rule TTP_XOR_QUAD_CurrentVersionRun_5b6b {
  strings:
    $key_5b6b = { 08 04 [2] 2c 0a [2] 07 26 [2] 29 04 [2] 3d 1f [2] 32 05 [2] 2c 18 [2] 2e 19 [2] 35 1f [2] 29 18 [2] 35 37 }

  condition:
    any of them
}