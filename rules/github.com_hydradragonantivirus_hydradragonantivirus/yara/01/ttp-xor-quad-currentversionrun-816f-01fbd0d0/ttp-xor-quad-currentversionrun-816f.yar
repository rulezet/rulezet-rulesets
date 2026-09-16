rule TTP_XOR_QUAD_CurrentVersionRun_816f {
  strings:
    $key_816f = { d2 00 [2] f6 0e [2] dd 22 [2] f3 00 [2] e7 1b [2] e8 01 [2] f6 1c [2] f4 1d [2] ef 1b [2] f3 1c [2] ef 33 }

  condition:
    any of them
}