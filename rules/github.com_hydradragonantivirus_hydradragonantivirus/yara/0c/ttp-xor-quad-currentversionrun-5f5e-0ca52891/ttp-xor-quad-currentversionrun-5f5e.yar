rule TTP_XOR_QUAD_CurrentVersionRun_5f5e {
  strings:
    $key_5f5e = { 0c 31 [2] 28 3f [2] 03 13 [2] 2d 31 [2] 39 2a [2] 36 30 [2] 28 2d [2] 2a 2c [2] 31 2a [2] 2d 2d [2] 31 02 }

  condition:
    any of them
}