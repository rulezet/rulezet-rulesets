rule TTP_XOR_QUAD_CurrentVersionRun_811f {
  strings:
    $key_811f = { d2 70 [2] f6 7e [2] dd 52 [2] f3 70 [2] e7 6b [2] e8 71 [2] f6 6c [2] f4 6d [2] ef 6b [2] f3 6c [2] ef 43 }

  condition:
    any of them
}