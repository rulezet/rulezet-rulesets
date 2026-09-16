rule TTP_XOR_QUAD_CurrentVersionRun_9a6f {
  strings:
    $key_9a6f = { c9 00 [2] ed 0e [2] c6 22 [2] e8 00 [2] fc 1b [2] f3 01 [2] ed 1c [2] ef 1d [2] f4 1b [2] e8 1c [2] f4 33 }

  condition:
    any of them
}