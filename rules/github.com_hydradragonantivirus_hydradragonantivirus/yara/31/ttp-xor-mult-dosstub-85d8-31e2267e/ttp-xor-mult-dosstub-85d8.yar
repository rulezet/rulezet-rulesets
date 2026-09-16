rule TTP_XOR_MULT_DOSStub_85d8 {
  strings:
    $key_85d8 = { d1 b0 [2] a5 a8 [2] e2 aa [2] a5 bb [2] eb b7 [2] e7 bd [2] f0 b6 [2] eb f8 [2] d6 }

  condition:
    any of them
}