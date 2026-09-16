rule TTP_XOR_QUAD_CurrentVersionRun_84e6 {
  strings:
    $key_84e6 = { d7 89 [2] f3 87 [2] d8 ab [2] f6 89 [2] e2 92 [2] ed 88 [2] f3 95 [2] f1 94 [2] ea 92 [2] f6 95 [2] ea ba }

  condition:
    any of them
}