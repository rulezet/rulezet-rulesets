rule TTP_XOR_QUAD_CurrentVersionRun_5b2e {
  strings:
    $key_5b2e = { 08 41 [2] 2c 4f [2] 07 63 [2] 29 41 [2] 3d 5a [2] 32 40 [2] 2c 5d [2] 2e 5c [2] 35 5a [2] 29 5d [2] 35 72 }

  condition:
    any of them
}