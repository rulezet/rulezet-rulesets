rule TTP_XOR_QUAD_CurrentVersionRun_8698 {
  strings:
    $key_8698 = { d5 f7 [2] f1 f9 [2] da d5 [2] f4 f7 [2] e0 ec [2] ef f6 [2] f1 eb [2] f3 ea [2] e8 ec [2] f4 eb [2] e8 c4 }

  condition:
    any of them
}