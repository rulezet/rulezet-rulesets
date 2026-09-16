rule TTP_XOR_QUAD_CurrentVersionRun_810a {
  strings:
    $key_810a = { d2 65 [2] f6 6b [2] dd 47 [2] f3 65 [2] e7 7e [2] e8 64 [2] f6 79 [2] f4 78 [2] ef 7e [2] f3 79 [2] ef 56 }

  condition:
    any of them
}