rule TTP_XOR_MULT_DOSStub_90c4 {
  strings:
    $key_90c4 = { c4 ac [2] b0 b4 [2] f7 b6 [2] b0 a7 [2] fe ab [2] f2 a1 [2] e5 aa [2] fe e4 [2] c3 }

  condition:
    any of them
}