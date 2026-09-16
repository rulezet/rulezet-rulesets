rule TTP_XOR_QUAD_CurrentVersionRun_811c {
  strings:
    $key_811c = { d2 73 [2] f6 7d [2] dd 51 [2] f3 73 [2] e7 68 [2] e8 72 [2] f6 6f [2] f4 6e [2] ef 68 [2] f3 6f [2] ef 40 }

  condition:
    any of them
}