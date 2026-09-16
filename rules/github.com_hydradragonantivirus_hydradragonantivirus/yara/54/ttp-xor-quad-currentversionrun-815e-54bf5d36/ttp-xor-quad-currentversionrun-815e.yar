rule TTP_XOR_QUAD_CurrentVersionRun_815e {
  strings:
    $key_815e = { d2 31 [2] f6 3f [2] dd 13 [2] f3 31 [2] e7 2a [2] e8 30 [2] f6 2d [2] f4 2c [2] ef 2a [2] f3 2d [2] ef 02 }

  condition:
    any of them
}