rule TTP_XOR_QUAD_CurrentVersionRun_815a {
  strings:
    $key_815a = { d2 35 [2] f6 3b [2] dd 17 [2] f3 35 [2] e7 2e [2] e8 34 [2] f6 29 [2] f4 28 [2] ef 2e [2] f3 29 [2] ef 06 }

  condition:
    any of them
}