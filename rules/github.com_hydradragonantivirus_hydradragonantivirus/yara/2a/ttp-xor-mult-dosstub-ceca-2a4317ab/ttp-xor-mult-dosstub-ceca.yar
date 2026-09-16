rule TTP_XOR_MULT_DOSStub_ceca {
  strings:
    $key_ceca = { 9a a2 [2] ee ba [2] a9 b8 [2] ee a9 [2] a0 a5 [2] ac af [2] bb a4 [2] a0 ea [2] 9d }

  condition:
    any of them
}