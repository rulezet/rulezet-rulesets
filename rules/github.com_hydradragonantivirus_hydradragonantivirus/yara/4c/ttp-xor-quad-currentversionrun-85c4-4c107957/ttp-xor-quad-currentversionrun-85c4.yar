rule TTP_XOR_QUAD_CurrentVersionRun_85c4 {
  strings:
    $key_85c4 = { d6 ab [2] f2 a5 [2] d9 89 [2] f7 ab [2] e3 b0 [2] ec aa [2] f2 b7 [2] f0 b6 [2] eb b0 [2] f7 b7 [2] eb 98 }

  condition:
    any of them
}