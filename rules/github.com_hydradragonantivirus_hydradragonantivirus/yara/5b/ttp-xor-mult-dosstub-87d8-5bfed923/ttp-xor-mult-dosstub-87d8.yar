rule TTP_XOR_MULT_DOSStub_87d8 {
  strings:
    $key_87d8 = { d3 b0 [2] a7 a8 [2] e0 aa [2] a7 bb [2] e9 b7 [2] e5 bd [2] f2 b6 [2] e9 f8 [2] d4 }

  condition:
    any of them
}