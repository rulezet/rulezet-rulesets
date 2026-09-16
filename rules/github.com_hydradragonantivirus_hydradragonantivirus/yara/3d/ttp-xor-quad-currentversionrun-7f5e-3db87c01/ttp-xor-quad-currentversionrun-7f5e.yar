rule TTP_XOR_QUAD_CurrentVersionRun_7f5e {
  strings:
    $key_7f5e = { 2c 31 [2] 08 3f [2] 23 13 [2] 0d 31 [2] 19 2a [2] 16 30 [2] 08 2d [2] 0a 2c [2] 11 2a [2] 0d 2d [2] 11 02 }

  condition:
    any of them
}