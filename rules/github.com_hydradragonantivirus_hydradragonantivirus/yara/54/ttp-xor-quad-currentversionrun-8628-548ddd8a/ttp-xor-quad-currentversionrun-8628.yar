rule TTP_XOR_QUAD_CurrentVersionRun_8628 {
  strings:
    $key_8628 = { d5 47 [2] f1 49 [2] da 65 [2] f4 47 [2] e0 5c [2] ef 46 [2] f1 5b [2] f3 5a [2] e8 5c [2] f4 5b [2] e8 74 }

  condition:
    any of them
}