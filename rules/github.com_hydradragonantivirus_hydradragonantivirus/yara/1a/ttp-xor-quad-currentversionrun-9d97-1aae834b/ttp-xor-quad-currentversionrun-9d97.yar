rule TTP_XOR_QUAD_CurrentVersionRun_9d97 {
  strings:
    $key_9d97 = { ce f8 [2] ea f6 [2] c1 da [2] ef f8 [2] fb e3 [2] f4 f9 [2] ea e4 [2] e8 e5 [2] f3 e3 [2] ef e4 [2] f3 cb }

  condition:
    any of them
}