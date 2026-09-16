rule TTP_XOR_MULT_DOSStub_95d8 {
  strings:
    $key_95d8 = { c1 b0 [2] b5 a8 [2] f2 aa [2] b5 bb [2] fb b7 [2] f7 bd [2] e0 b6 [2] fb f8 [2] c6 }

  condition:
    any of them
}