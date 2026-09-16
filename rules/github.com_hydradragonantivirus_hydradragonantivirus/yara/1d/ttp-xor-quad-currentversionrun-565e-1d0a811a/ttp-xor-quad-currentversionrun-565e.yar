rule TTP_XOR_QUAD_CurrentVersionRun_565e {
  strings:
    $key_565e = { 05 31 [2] 21 3f [2] 0a 13 [2] 24 31 [2] 30 2a [2] 3f 30 [2] 21 2d [2] 23 2c [2] 38 2a [2] 24 2d [2] 38 02 }

  condition:
    any of them
}