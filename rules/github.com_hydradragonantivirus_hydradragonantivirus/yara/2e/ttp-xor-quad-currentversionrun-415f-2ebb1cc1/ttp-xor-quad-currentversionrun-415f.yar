rule TTP_XOR_QUAD_CurrentVersionRun_415f {
  strings:
    $key_415f = { 12 30 [2] 36 3e [2] 1d 12 [2] 33 30 [2] 27 2b [2] 28 31 [2] 36 2c [2] 34 2d [2] 2f 2b [2] 33 2c [2] 2f 03 }

  condition:
    any of them
}