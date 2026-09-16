rule TTP_XOR_QUAD_CurrentVersionRun_8184 {
  strings:
    $key_8184 = { d2 eb [2] f6 e5 [2] dd c9 [2] f3 eb [2] e7 f0 [2] e8 ea [2] f6 f7 [2] f4 f6 [2] ef f0 [2] f3 f7 [2] ef d8 }

  condition:
    any of them
}