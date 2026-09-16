rule TTP_XOR_QUAD_CurrentVersionRun_8699 {
  strings:
    $key_8699 = { d5 f6 [2] f1 f8 [2] da d4 [2] f4 f6 [2] e0 ed [2] ef f7 [2] f1 ea [2] f3 eb [2] e8 ed [2] f4 ea [2] e8 c5 }

  condition:
    any of them
}