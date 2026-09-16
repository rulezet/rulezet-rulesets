rule TTP_XOR_QUAD_CurrentVersionRun_735e {
  strings:
    $key_735e = { 20 31 [2] 04 3f [2] 2f 13 [2] 01 31 [2] 15 2a [2] 1a 30 [2] 04 2d [2] 06 2c [2] 1d 2a [2] 01 2d [2] 1d 02 }

  condition:
    any of them
}