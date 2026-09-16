rule TTP_XOR_MULT_DOSStub_95c9 {
  strings:
    $key_95c9 = { c1 a1 [2] b5 b9 [2] f2 bb [2] b5 aa [2] fb a6 [2] f7 ac [2] e0 a7 [2] fb e9 [2] c6 }

  condition:
    any of them
}