rule TTP_XOR_QUAD_CurrentVersionRun_8fc5 {
  strings:
    $key_8fc5 = { dc aa [2] f8 a4 [2] d3 88 [2] fd aa [2] e9 b1 [2] e6 ab [2] f8 b6 [2] fa b7 [2] e1 b1 [2] fd b6 [2] e1 99 }

  condition:
    any of them
}