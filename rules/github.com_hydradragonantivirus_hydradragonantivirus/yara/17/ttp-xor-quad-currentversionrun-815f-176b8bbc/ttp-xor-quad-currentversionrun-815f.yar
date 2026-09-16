rule TTP_XOR_QUAD_CurrentVersionRun_815f {
  strings:
    $key_815f = { d2 30 [2] f6 3e [2] dd 12 [2] f3 30 [2] e7 2b [2] e8 31 [2] f6 2c [2] f4 2d [2] ef 2b [2] f3 2c [2] ef 03 }

  condition:
    any of them
}