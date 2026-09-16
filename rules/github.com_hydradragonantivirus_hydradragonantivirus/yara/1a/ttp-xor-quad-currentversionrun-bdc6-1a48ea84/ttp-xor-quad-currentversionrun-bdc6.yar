rule TTP_XOR_QUAD_CurrentVersionRun_bdc6 {
  strings:
    $key_bdc6 = { ee a9 [2] ca a7 [2] e1 8b [2] cf a9 [2] db b2 [2] d4 a8 [2] ca b5 [2] c8 b4 [2] d3 b2 [2] cf b5 [2] d3 9a }

  condition:
    any of them
}