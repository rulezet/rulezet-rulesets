rule TTP_XOR_QUAD_CurrentVersionRun_94e6 {
  strings:
    $key_94e6 = { c7 89 [2] e3 87 [2] c8 ab [2] e6 89 [2] f2 92 [2] fd 88 [2] e3 95 [2] e1 94 [2] fa 92 [2] e6 95 [2] fa ba }

  condition:
    any of them
}