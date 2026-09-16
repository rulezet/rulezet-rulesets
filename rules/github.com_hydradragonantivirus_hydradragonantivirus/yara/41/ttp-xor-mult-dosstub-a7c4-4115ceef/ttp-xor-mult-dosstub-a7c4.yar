rule TTP_XOR_MULT_DOSStub_a7c4 {
  strings:
    $key_a7c4 = { f3 ac [2] 87 b4 [2] c0 b6 [2] 87 a7 [2] c9 ab [2] c5 a1 [2] d2 aa [2] c9 e4 [2] f4 }

  condition:
    any of them
}