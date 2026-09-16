rule TTP_XOR_MULT_DOSStub_a2d8 {
  strings:
    $key_a2d8 = { f6 b0 [2] 82 a8 [2] c5 aa [2] 82 bb [2] cc b7 [2] c0 bd [2] d7 b6 [2] cc f8 [2] f1 }

  condition:
    any of them
}