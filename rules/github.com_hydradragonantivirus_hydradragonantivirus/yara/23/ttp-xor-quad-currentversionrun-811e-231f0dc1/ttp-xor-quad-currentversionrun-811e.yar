rule TTP_XOR_QUAD_CurrentVersionRun_811e {
  strings:
    $key_811e = { d2 71 [2] f6 7f [2] dd 53 [2] f3 71 [2] e7 6a [2] e8 70 [2] f6 6d [2] f4 6c [2] ef 6a [2] f3 6d [2] ef 42 }

  condition:
    any of them
}