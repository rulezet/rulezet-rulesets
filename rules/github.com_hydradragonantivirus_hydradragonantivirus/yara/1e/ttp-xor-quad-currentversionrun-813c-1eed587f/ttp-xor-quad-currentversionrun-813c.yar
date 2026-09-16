rule TTP_XOR_QUAD_CurrentVersionRun_813c {
  strings:
    $key_813c = { d2 53 [2] f6 5d [2] dd 71 [2] f3 53 [2] e7 48 [2] e8 52 [2] f6 4f [2] f4 4e [2] ef 48 [2] f3 4f [2] ef 60 }

  condition:
    any of them
}