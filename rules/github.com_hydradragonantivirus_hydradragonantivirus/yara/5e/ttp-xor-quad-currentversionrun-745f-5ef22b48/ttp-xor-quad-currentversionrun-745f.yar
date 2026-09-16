rule TTP_XOR_QUAD_CurrentVersionRun_745f {
  strings:
    $key_745f = { 27 30 [2] 03 3e [2] 28 12 [2] 06 30 [2] 12 2b [2] 1d 31 [2] 03 2c [2] 01 2d [2] 1a 2b [2] 06 2c [2] 1a 03 }

  condition:
    any of them
}