rule TTP_XOR_QUAD_CurrentVersionRun_99c6 {
  strings:
    $key_99c6 = { ca a9 [2] ee a7 [2] c5 8b [2] eb a9 [2] ff b2 [2] f0 a8 [2] ee b5 [2] ec b4 [2] f7 b2 [2] eb b5 [2] f7 9a }

  condition:
    any of them
}