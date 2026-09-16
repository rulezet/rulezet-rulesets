rule TTP_XOR_MULT_DOSStub_cec4 {
  strings:
    $key_cec4 = { 9a ac [2] ee b4 [2] a9 b6 [2] ee a7 [2] a0 ab [2] ac a1 [2] bb aa [2] a0 e4 [2] 9d }

  condition:
    any of them
}