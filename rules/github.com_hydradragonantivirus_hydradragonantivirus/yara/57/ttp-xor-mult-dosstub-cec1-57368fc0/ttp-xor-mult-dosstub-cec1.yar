rule TTP_XOR_MULT_DOSStub_cec1 {
  strings:
    $key_cec1 = { 9a a9 [2] ee b1 [2] a9 b3 [2] ee a2 [2] a0 ae [2] ac a4 [2] bb af [2] a0 e1 [2] 9d }

  condition:
    any of them
}