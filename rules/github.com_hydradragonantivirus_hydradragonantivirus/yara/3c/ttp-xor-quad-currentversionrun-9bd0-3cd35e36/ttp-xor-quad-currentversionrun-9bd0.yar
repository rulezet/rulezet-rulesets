rule TTP_XOR_QUAD_CurrentVersionRun_9bd0 {
  strings:
    $key_9bd0 = { c8 bf [2] ec b1 [2] c7 9d [2] e9 bf [2] fd a4 [2] f2 be [2] ec a3 [2] ee a2 [2] f5 a4 [2] e9 a3 [2] f5 8c }

  condition:
    any of them
}