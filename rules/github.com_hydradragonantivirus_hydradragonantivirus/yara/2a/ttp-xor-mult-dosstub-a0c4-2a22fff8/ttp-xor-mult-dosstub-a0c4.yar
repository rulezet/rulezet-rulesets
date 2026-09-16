rule TTP_XOR_MULT_DOSStub_a0c4 {
  strings:
    $key_a0c4 = { f4 ac [2] 80 b4 [2] c7 b6 [2] 80 a7 [2] ce ab [2] c2 a1 [2] d5 aa [2] ce e4 [2] f3 }

  condition:
    any of them
}