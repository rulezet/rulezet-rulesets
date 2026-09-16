rule TTP_XOR_MULT_DOSStub_d4c2 {
  strings:
    $key_d4c2 = { 80 aa [2] f4 b2 [2] b3 b0 [2] f4 a1 [2] ba ad [2] b6 a7 [2] a1 ac [2] ba e2 [2] 87 }

  condition:
    any of them
}