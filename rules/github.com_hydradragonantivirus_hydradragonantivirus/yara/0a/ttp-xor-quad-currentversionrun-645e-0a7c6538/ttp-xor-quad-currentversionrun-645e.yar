rule TTP_XOR_QUAD_CurrentVersionRun_645e {
  strings:
    $key_645e = { 37 31 [2] 13 3f [2] 38 13 [2] 16 31 [2] 02 2a [2] 0d 30 [2] 13 2d [2] 11 2c [2] 0a 2a [2] 16 2d [2] 0a 02 }

  condition:
    any of them
}