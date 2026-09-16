rule TTP_XOR_QUAD_CurrentVersionRun_814a {
  strings:
    $key_814a = { d2 25 [2] f6 2b [2] dd 07 [2] f3 25 [2] e7 3e [2] e8 24 [2] f6 39 [2] f4 38 [2] ef 3e [2] f3 39 [2] ef 16 }

  condition:
    any of them
}