rule TTP_XOR_QUAD_CurrentVersionRun_83d8 {
  strings:
    $key_83d8 = { d0 b7 [2] f4 b9 [2] df 95 [2] f1 b7 [2] e5 ac [2] ea b6 [2] f4 ab [2] f6 aa [2] ed ac [2] f1 ab [2] ed 84 }

  condition:
    any of them
}