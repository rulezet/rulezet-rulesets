rule TTP_XOR_MULT_DOSStub_90c9 {
  strings:
    $key_90c9 = { c4 a1 [2] b0 b9 [2] f7 bb [2] b0 aa [2] fe a6 [2] f2 ac [2] e5 a7 [2] fe e9 [2] c3 }

  condition:
    any of them
}