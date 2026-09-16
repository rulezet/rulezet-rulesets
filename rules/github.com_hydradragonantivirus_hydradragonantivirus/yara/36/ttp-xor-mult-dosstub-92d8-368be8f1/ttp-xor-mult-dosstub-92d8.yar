rule TTP_XOR_MULT_DOSStub_92d8 {
  strings:
    $key_92d8 = { c6 b0 [2] b2 a8 [2] f5 aa [2] b2 bb [2] fc b7 [2] f0 bd [2] e7 b6 [2] fc f8 [2] c1 }

  condition:
    any of them
}