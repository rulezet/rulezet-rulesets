rule TTP_XOR_QUAD_CurrentVersionRun_813f {
  strings:
    $key_813f = { d2 50 [2] f6 5e [2] dd 72 [2] f3 50 [2] e7 4b [2] e8 51 [2] f6 4c [2] f4 4d [2] ef 4b [2] f3 4c [2] ef 63 }

  condition:
    any of them
}