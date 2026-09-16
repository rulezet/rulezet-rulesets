rule TTP_XOR_MULT_DOSStub_90c2 {
  strings:
    $key_90c2 = { c4 aa [2] b0 b2 [2] f7 b0 [2] b0 a1 [2] fe ad [2] f2 a7 [2] e5 ac [2] fe e2 [2] c3 }

  condition:
    any of them
}