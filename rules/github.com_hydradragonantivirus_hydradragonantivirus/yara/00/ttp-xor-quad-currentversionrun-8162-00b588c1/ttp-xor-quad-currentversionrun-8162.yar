rule TTP_XOR_QUAD_CurrentVersionRun_8162 {
  strings:
    $key_8162 = { d2 0d [2] f6 03 [2] dd 2f [2] f3 0d [2] e7 16 [2] e8 0c [2] f6 11 [2] f4 10 [2] ef 16 [2] f3 11 [2] ef 3e }

  condition:
    any of them
}