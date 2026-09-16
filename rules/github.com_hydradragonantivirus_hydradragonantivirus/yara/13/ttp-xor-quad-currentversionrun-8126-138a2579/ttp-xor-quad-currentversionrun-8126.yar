rule TTP_XOR_QUAD_CurrentVersionRun_8126 {
  strings:
    $key_8126 = { d2 49 [2] f6 47 [2] dd 6b [2] f3 49 [2] e7 52 [2] e8 48 [2] f6 55 [2] f4 54 [2] ef 52 [2] f3 55 [2] ef 7a }

  condition:
    any of them
}