rule TTP_XOR_QUAD_CurrentVersionRun_99d2 {
  strings:
    $key_99d2 = { ca bd [2] ee b3 [2] c5 9f [2] eb bd [2] ff a6 [2] f0 bc [2] ee a1 [2] ec a0 [2] f7 a6 [2] eb a1 [2] f7 8e }

  condition:
    any of them
}