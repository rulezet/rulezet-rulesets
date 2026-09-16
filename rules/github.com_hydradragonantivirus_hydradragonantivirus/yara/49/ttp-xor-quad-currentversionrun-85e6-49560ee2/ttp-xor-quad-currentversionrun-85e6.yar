rule TTP_XOR_QUAD_CurrentVersionRun_85e6 {
  strings:
    $key_85e6 = { d6 89 [2] f2 87 [2] d9 ab [2] f7 89 [2] e3 92 [2] ec 88 [2] f2 95 [2] f0 94 [2] eb 92 [2] f7 95 [2] eb ba }

  condition:
    any of them
}