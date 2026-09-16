rule TTP_XOR_QUAD_CurrentVersionRun_94c5 {
  strings:
    $key_94c5 = { c7 aa [2] e3 a4 [2] c8 88 [2] e6 aa [2] f2 b1 [2] fd ab [2] e3 b6 [2] e1 b7 [2] fa b1 [2] e6 b6 [2] fa 99 }

  condition:
    any of them
}