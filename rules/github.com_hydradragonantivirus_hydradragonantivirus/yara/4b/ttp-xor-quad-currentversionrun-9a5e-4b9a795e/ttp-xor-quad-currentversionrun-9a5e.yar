rule TTP_XOR_QUAD_CurrentVersionRun_9a5e {
  strings:
    $key_9a5e = { c9 31 [2] ed 3f [2] c6 13 [2] e8 31 [2] fc 2a [2] f3 30 [2] ed 2d [2] ef 2c [2] f4 2a [2] e8 2d [2] f4 02 }

  condition:
    any of them
}