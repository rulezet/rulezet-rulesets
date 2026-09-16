rule TTP_XOR_MULT_DOSStub_ced1 {
  strings:
    $key_ced1 = { 9a b9 [2] ee a1 [2] a9 a3 [2] ee b2 [2] a0 be [2] ac b4 [2] bb bf [2] a0 f1 [2] 9d }

  condition:
    any of them
}