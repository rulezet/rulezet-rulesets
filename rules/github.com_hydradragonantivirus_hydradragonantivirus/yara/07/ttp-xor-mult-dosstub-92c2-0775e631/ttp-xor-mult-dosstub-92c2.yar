rule TTP_XOR_MULT_DOSStub_92c2 {
  strings:
    $key_92c2 = { c6 aa [2] b2 b2 [2] f5 b0 [2] b2 a1 [2] fc ad [2] f0 a7 [2] e7 ac [2] fc e2 [2] c1 }

  condition:
    any of them
}