rule TTP_XOR_QUAD_CurrentVersionRun_815d {
  strings:
    $key_815d = { d2 32 [2] f6 3c [2] dd 10 [2] f3 32 [2] e7 29 [2] e8 33 [2] f6 2e [2] f4 2f [2] ef 29 [2] f3 2e [2] ef 01 }

  condition:
    any of them
}