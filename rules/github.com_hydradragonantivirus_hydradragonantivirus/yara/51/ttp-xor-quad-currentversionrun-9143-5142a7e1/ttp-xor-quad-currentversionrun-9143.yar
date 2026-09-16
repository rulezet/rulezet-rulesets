rule TTP_XOR_QUAD_CurrentVersionRun_9143 {
  strings:
    $key_9143 = { c2 2c [2] e6 22 [2] cd 0e [2] e3 2c [2] f7 37 [2] f8 2d [2] e6 30 [2] e4 31 [2] ff 37 [2] e3 30 [2] ff 1f }

  condition:
    any of them
}