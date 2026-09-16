rule TTP_XOR_QUAD_CurrentVersionRun_9a4d {
  strings:
    $key_9a4d = { c9 22 [2] ed 2c [2] c6 00 [2] e8 22 [2] fc 39 [2] f3 23 [2] ed 3e [2] ef 3f [2] f4 39 [2] e8 3e [2] f4 11 }

  condition:
    any of them
}