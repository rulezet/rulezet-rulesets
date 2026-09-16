rule TTP_XOR_QUAD_CurrentVersionRun_817a {
  strings:
    $key_817a = { d2 15 [2] f6 1b [2] dd 37 [2] f3 15 [2] e7 0e [2] e8 14 [2] f6 09 [2] f4 08 [2] ef 0e [2] f3 09 [2] ef 26 }

  condition:
    any of them
}