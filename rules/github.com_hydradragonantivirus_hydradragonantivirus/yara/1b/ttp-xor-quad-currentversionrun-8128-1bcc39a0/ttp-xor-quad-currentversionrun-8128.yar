rule TTP_XOR_QUAD_CurrentVersionRun_8128 {
  strings:
    $key_8128 = { d2 47 [2] f6 49 [2] dd 65 [2] f3 47 [2] e7 5c [2] e8 46 [2] f6 5b [2] f4 5a [2] ef 5c [2] f3 5b [2] ef 74 }

  condition:
    any of them
}