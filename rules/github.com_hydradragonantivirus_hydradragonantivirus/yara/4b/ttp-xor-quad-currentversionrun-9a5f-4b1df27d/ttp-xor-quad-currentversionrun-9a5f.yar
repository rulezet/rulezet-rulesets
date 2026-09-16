rule TTP_XOR_QUAD_CurrentVersionRun_9a5f {
  strings:
    $key_9a5f = { c9 30 [2] ed 3e [2] c6 12 [2] e8 30 [2] fc 2b [2] f3 31 [2] ed 2c [2] ef 2d [2] f4 2b [2] e8 2c [2] f4 03 }

  condition:
    any of them
}