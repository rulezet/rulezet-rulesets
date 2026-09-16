rule TTP_XOR_MULT_DOSStub_ced9 {
  strings:
    $key_ced9 = { 9a b1 [2] ee a9 [2] a9 ab [2] ee ba [2] a0 b6 [2] ac bc [2] bb b7 [2] a0 f9 [2] 9d }

  condition:
    any of them
}