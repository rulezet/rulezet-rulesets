rule TTP_XOR_QUAD_CurrentVersionRun_810e {
  strings:
    $key_810e = { d2 61 [2] f6 6f [2] dd 43 [2] f3 61 [2] e7 7a [2] e8 60 [2] f6 7d [2] f4 7c [2] ef 7a [2] f3 7d [2] ef 52 }

  condition:
    any of them
}