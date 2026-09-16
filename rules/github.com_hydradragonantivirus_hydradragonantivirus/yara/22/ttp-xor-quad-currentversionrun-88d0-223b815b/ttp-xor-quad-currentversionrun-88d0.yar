rule TTP_XOR_QUAD_CurrentVersionRun_88d0 {
  strings:
    $key_88d0 = { db bf [2] ff b1 [2] d4 9d [2] fa bf [2] ee a4 [2] e1 be [2] ff a3 [2] fd a2 [2] e6 a4 [2] fa a3 [2] e6 8c }

  condition:
    any of them
}