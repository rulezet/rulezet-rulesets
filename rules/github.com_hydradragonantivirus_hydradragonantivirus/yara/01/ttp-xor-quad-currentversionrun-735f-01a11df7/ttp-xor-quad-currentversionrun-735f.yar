rule TTP_XOR_QUAD_CurrentVersionRun_735f {
  strings:
    $key_735f = { 20 30 [2] 04 3e [2] 2f 12 [2] 01 30 [2] 15 2b [2] 1a 31 [2] 04 2c [2] 06 2d [2] 1d 2b [2] 01 2c [2] 1d 03 }

  condition:
    any of them
}