rule TTP_XOR_QUAD_CurrentVersionRun_5b55 {
  strings:
    $key_5b55 = { 08 3a [2] 2c 34 [2] 07 18 [2] 29 3a [2] 3d 21 [2] 32 3b [2] 2c 26 [2] 2e 27 [2] 35 21 [2] 29 26 [2] 35 09 }

  condition:
    any of them
}