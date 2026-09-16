rule TTP_XOR_QUAD_CurrentVersionRun_9bdb {
  strings:
    $key_9bdb = { c8 b4 [2] ec ba [2] c7 96 [2] e9 b4 [2] fd af [2] f2 b5 [2] ec a8 [2] ee a9 [2] f5 af [2] e9 a8 [2] f5 87 }

  condition:
    any of them
}