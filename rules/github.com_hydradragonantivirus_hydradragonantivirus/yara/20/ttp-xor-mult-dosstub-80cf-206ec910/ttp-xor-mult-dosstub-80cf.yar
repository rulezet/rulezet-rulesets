rule TTP_XOR_MULT_DOSStub_80cf {
  strings:
    $key_80cf = { d4 a7 [2] a0 bf [2] e7 bd [2] a0 ac [2] ee a0 [2] e2 aa [2] f5 a1 [2] ee ef [2] d3 }

  condition:
    any of them
}