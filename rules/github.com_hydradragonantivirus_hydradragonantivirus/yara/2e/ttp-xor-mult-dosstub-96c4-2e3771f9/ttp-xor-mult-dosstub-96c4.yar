rule TTP_XOR_MULT_DOSStub_96c4 {
  strings:
    $key_96c4 = { c2 ac [2] b6 b4 [2] f1 b6 [2] b6 a7 [2] f8 ab [2] f4 a1 [2] e3 aa [2] f8 e4 [2] c5 }

  condition:
    any of them
}