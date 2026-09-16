rule TTP_XOR_QUAD_CurrentVersionRun_8171 {
  strings:
    $key_8171 = { d2 1e [2] f6 10 [2] dd 3c [2] f3 1e [2] e7 05 [2] e8 1f [2] f6 02 [2] f4 03 [2] ef 05 [2] f3 02 [2] ef 2d }

  condition:
    any of them
}