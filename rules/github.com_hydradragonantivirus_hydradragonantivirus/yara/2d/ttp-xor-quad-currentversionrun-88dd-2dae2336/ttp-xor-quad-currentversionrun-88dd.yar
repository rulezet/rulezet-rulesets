rule TTP_XOR_QUAD_CurrentVersionRun_88dd {
  strings:
    $key_88dd = { db b2 [2] ff bc [2] d4 90 [2] fa b2 [2] ee a9 [2] e1 b3 [2] ff ae [2] fd af [2] e6 a9 [2] fa ae [2] e6 81 }

  condition:
    any of them
}