rule TTP_XOR_MULT_DOSStub_92c4 {
  strings:
    $key_92c4 = { c6 ac [2] b2 b4 [2] f5 b6 [2] b2 a7 [2] fc ab [2] f0 a1 [2] e7 aa [2] fc e4 [2] c1 }

  condition:
    any of them
}