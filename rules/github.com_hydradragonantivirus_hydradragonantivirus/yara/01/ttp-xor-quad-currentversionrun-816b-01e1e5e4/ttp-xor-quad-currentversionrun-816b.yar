rule TTP_XOR_QUAD_CurrentVersionRun_816b {
  strings:
    $key_816b = { d2 04 [2] f6 0a [2] dd 26 [2] f3 04 [2] e7 1f [2] e8 05 [2] f6 18 [2] f4 19 [2] ef 1f [2] f3 18 [2] ef 37 }

  condition:
    any of them
}