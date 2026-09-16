rule TTP_XOR_QUAD_CurrentVersionRun_465e {
  strings:
    $key_465e = { 15 31 [2] 31 3f [2] 1a 13 [2] 34 31 [2] 20 2a [2] 2f 30 [2] 31 2d [2] 33 2c [2] 28 2a [2] 34 2d [2] 28 02 }

  condition:
    any of them
}