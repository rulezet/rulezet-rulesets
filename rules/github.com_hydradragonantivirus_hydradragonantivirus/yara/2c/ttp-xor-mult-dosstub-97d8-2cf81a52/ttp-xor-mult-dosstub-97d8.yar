rule TTP_XOR_MULT_DOSStub_97d8 {
  strings:
    $key_97d8 = { c3 b0 [2] b7 a8 [2] f0 aa [2] b7 bb [2] f9 b7 [2] f5 bd [2] e2 b6 [2] f9 f8 [2] c4 }

  condition:
    any of them
}