rule TTP_XOR_QUAD_CurrentVersionRun_812e {
  strings:
    $key_812e = { d2 41 [2] f6 4f [2] dd 63 [2] f3 41 [2] e7 5a [2] e8 40 [2] f6 5d [2] f4 5c [2] ef 5a [2] f3 5d [2] ef 72 }

  condition:
    any of them
}