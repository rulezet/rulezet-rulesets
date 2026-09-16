rule TTP_XOR_QUAD_CurrentVersionRun_816e {
  strings:
    $key_816e = { d2 01 [2] f6 0f [2] dd 23 [2] f3 01 [2] e7 1a [2] e8 00 [2] f6 1d [2] f4 1c [2] ef 1a [2] f3 1d [2] ef 32 }

  condition:
    any of them
}