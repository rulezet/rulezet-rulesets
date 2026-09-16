rule TTP_XOR_QUAD_CurrentVersionRun_84d1 {
  strings:
    $key_84d1 = { d7 be [2] f3 b0 [2] d8 9c [2] f6 be [2] e2 a5 [2] ed bf [2] f3 a2 [2] f1 a3 [2] ea a5 [2] f6 a2 [2] ea 8d }

  condition:
    any of them
}