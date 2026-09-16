rule TTP_XOR_QUAD_CurrentVersionRun_8668 {
  strings:
    $key_8668 = { d5 07 [2] f1 09 [2] da 25 [2] f4 07 [2] e0 1c [2] ef 06 [2] f1 1b [2] f3 1a [2] e8 1c [2] f4 1b [2] e8 34 }

  condition:
    any of them
}