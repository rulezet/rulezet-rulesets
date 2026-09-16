rule TTP_XOR_QUAD_CurrentVersionRun_8183 {
  strings:
    $key_8183 = { d2 ec [2] f6 e2 [2] dd ce [2] f3 ec [2] e7 f7 [2] e8 ed [2] f6 f0 [2] f4 f1 [2] ef f7 [2] f3 f0 [2] ef df }

  condition:
    any of them
}