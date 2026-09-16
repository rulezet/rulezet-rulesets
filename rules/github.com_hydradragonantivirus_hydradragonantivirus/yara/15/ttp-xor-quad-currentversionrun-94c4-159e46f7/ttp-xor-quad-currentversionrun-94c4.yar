rule TTP_XOR_QUAD_CurrentVersionRun_94c4 {
  strings:
    $key_94c4 = { c7 ab [2] e3 a5 [2] c8 89 [2] e6 ab [2] f2 b0 [2] fd aa [2] e3 b7 [2] e1 b6 [2] fa b0 [2] e6 b7 [2] fa 98 }

  condition:
    any of them
}