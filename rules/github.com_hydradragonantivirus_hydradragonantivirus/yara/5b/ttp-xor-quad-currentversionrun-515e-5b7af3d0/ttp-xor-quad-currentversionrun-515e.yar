rule TTP_XOR_QUAD_CurrentVersionRun_515e {
  strings:
    $key_515e = { 02 31 [2] 26 3f [2] 0d 13 [2] 23 31 [2] 37 2a [2] 38 30 [2] 26 2d [2] 24 2c [2] 3f 2a [2] 23 2d [2] 3f 02 }

  condition:
    any of them
}