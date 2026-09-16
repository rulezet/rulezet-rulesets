rule TTP_XOR_QUAD_CurrentVersionRun_94d8 {
  strings:
    $key_94d8 = { c7 b7 [2] e3 b9 [2] c8 95 [2] e6 b7 [2] f2 ac [2] fd b6 [2] e3 ab [2] e1 aa [2] fa ac [2] e6 ab [2] fa 84 }

  condition:
    any of them
}