rule TTP_XOR_QUAD_CurrentVersionRun_861f {
  strings:
    $key_861f = { d5 70 [2] f1 7e [2] da 52 [2] f4 70 [2] e0 6b [2] ef 71 [2] f1 6c [2] f3 6d [2] e8 6b [2] f4 6c [2] e8 43 }

  condition:
    any of them
}