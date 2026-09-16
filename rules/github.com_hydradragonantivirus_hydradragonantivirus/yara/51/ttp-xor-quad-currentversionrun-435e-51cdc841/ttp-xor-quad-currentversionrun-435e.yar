rule TTP_XOR_QUAD_CurrentVersionRun_435e {
  strings:
    $key_435e = { 10 31 [2] 34 3f [2] 1f 13 [2] 31 31 [2] 25 2a [2] 2a 30 [2] 34 2d [2] 36 2c [2] 2d 2a [2] 31 2d [2] 2d 02 }

  condition:
    any of them
}