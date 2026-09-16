rule TTP_XOR_QUAD_CurrentVersionRun_99da {
  strings:
    $key_99da = { ca b5 [2] ee bb [2] c5 97 [2] eb b5 [2] ff ae [2] f0 b4 [2] ee a9 [2] ec a8 [2] f7 ae [2] eb a9 [2] f7 86 }

  condition:
    any of them
}