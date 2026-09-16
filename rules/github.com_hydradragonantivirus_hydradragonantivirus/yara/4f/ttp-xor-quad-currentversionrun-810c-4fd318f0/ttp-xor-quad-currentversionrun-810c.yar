rule TTP_XOR_QUAD_CurrentVersionRun_810c {
  strings:
    $key_810c = { d2 63 [2] f6 6d [2] dd 41 [2] f3 63 [2] e7 78 [2] e8 62 [2] f6 7f [2] f4 7e [2] ef 78 [2] f3 7f [2] ef 50 }

  condition:
    any of them
}