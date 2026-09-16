rule TTP_XOR_QUAD_CurrentVersionRun_5b7e {
  strings:
    $key_5b7e = { 08 11 [2] 2c 1f [2] 07 33 [2] 29 11 [2] 3d 0a [2] 32 10 [2] 2c 0d [2] 2e 0c [2] 35 0a [2] 29 0d [2] 35 22 }

  condition:
    any of them
}