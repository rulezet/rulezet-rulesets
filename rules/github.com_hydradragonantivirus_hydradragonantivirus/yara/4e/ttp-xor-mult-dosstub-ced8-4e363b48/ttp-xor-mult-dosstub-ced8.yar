rule TTP_XOR_MULT_DOSStub_ced8 {
  strings:
    $key_ced8 = { 9a b0 [2] ee a8 [2] a9 aa [2] ee bb [2] a0 b7 [2] ac bd [2] bb b6 [2] a0 f8 [2] 9d }

  condition:
    any of them
}