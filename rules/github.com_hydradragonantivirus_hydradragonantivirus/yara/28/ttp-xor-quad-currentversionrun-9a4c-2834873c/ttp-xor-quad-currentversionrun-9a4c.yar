rule TTP_XOR_QUAD_CurrentVersionRun_9a4c {
  strings:
    $key_9a4c = { c9 23 [2] ed 2d [2] c6 01 [2] e8 23 [2] fc 38 [2] f3 22 [2] ed 3f [2] ef 3e [2] f4 38 [2] e8 3f [2] f4 10 }

  condition:
    any of them
}