rule TTP_XOR_QUAD_CurrentVersionRun_99c7 {
  strings:
    $key_99c7 = { ca a8 [2] ee a6 [2] c5 8a [2] eb a8 [2] ff b3 [2] f0 a9 [2] ee b4 [2] ec b5 [2] f7 b3 [2] eb b4 [2] f7 9b }

  condition:
    any of them
}