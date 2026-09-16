rule TTP_XOR_MULT_DOSStub_cec2 {
  strings:
    $key_cec2 = { 9a aa [2] ee b2 [2] a9 b0 [2] ee a1 [2] a0 ad [2] ac a7 [2] bb ac [2] a0 e2 [2] 9d }

  condition:
    any of them
}