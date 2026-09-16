rule TTP_XOR_QUAD_CurrentVersionRun_99db {
  strings:
    $key_99db = { ca b4 [2] ee ba [2] c5 96 [2] eb b4 [2] ff af [2] f0 b5 [2] ee a8 [2] ec a9 [2] f7 af [2] eb a8 [2] f7 87 }

  condition:
    any of them
}