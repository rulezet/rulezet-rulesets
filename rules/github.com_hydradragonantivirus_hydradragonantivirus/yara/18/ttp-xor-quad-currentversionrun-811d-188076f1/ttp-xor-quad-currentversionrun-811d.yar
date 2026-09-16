rule TTP_XOR_QUAD_CurrentVersionRun_811d {
  strings:
    $key_811d = { d2 72 [2] f6 7c [2] dd 50 [2] f3 72 [2] e7 69 [2] e8 73 [2] f6 6e [2] f4 6f [2] ef 69 [2] f3 6e [2] ef 41 }

  condition:
    any of them
}