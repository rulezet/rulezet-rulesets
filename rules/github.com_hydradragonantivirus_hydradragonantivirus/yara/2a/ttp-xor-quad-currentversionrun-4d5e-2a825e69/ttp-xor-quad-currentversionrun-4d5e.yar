rule TTP_XOR_QUAD_CurrentVersionRun_4d5e {
  strings:
    $key_4d5e = { 1e 31 [2] 3a 3f [2] 11 13 [2] 3f 31 [2] 2b 2a [2] 24 30 [2] 3a 2d [2] 38 2c [2] 23 2a [2] 3f 2d [2] 23 02 }

  condition:
    any of them
}