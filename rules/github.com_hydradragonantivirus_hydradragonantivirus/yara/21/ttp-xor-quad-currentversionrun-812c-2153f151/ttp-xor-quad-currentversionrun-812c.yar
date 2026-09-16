rule TTP_XOR_QUAD_CurrentVersionRun_812c {
  strings:
    $key_812c = { d2 43 [2] f6 4d [2] dd 61 [2] f3 43 [2] e7 58 [2] e8 42 [2] f6 5f [2] f4 5e [2] ef 58 [2] f3 5f [2] ef 70 }

  condition:
    any of them
}