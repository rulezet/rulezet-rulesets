rule TTP_XOR_QUAD_CurrentVersionRun_5b29 {
  strings:
    $key_5b29 = { 08 46 [2] 2c 48 [2] 07 64 [2] 29 46 [2] 3d 5d [2] 32 47 [2] 2c 5a [2] 2e 5b [2] 35 5d [2] 29 5a [2] 35 75 }

  condition:
    any of them
}