rule TTP_XOR_QUAD_CurrentVersionRun_88dc {
  strings:
    $key_88dc = { db b3 [2] ff bd [2] d4 91 [2] fa b3 [2] ee a8 [2] e1 b2 [2] ff af [2] fd ae [2] e6 a8 [2] fa af [2] e6 80 }

  condition:
    any of them
}