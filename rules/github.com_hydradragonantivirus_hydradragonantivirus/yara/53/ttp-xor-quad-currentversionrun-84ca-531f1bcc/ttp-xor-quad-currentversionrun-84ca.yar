rule TTP_XOR_QUAD_CurrentVersionRun_84ca {
  strings:
    $key_84ca = { d7 a5 [2] f3 ab [2] d8 87 [2] f6 a5 [2] e2 be [2] ed a4 [2] f3 b9 [2] f1 b8 [2] ea be [2] f6 b9 [2] ea 96 }

  condition:
    any of them
}