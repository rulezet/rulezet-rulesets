rule TTP_XOR_QUAD_CurrentVersionRun_84c5 {
  strings:
    $key_84c5 = { d7 aa [2] f3 a4 [2] d8 88 [2] f6 aa [2] e2 b1 [2] ed ab [2] f3 b6 [2] f1 b7 [2] ea b1 [2] f6 b6 [2] ea 99 }

  condition:
    any of them
}