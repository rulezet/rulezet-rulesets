rule TTP_XOR_QUAD_CurrentVersionRun_812f {
  strings:
    $key_812f = { d2 40 [2] f6 4e [2] dd 62 [2] f3 40 [2] e7 5b [2] e8 41 [2] f6 5c [2] f4 5d [2] ef 5b [2] f3 5c [2] ef 73 }

  condition:
    any of them
}