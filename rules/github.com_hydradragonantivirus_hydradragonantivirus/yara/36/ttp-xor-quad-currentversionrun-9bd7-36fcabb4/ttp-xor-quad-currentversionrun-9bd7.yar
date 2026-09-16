rule TTP_XOR_QUAD_CurrentVersionRun_9bd7 {
  strings:
    $key_9bd7 = { c8 b8 [2] ec b6 [2] c7 9a [2] e9 b8 [2] fd a3 [2] f2 b9 [2] ec a4 [2] ee a5 [2] f5 a3 [2] e9 a4 [2] f5 8b }

  condition:
    any of them
}