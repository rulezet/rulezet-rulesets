rule TTP_XOR_MULT_DOSStub_90d8 {
  strings:
    $key_90d8 = { c4 b0 [2] b0 a8 [2] f7 aa [2] b0 bb [2] fe b7 [2] f2 bd [2] e5 b6 [2] fe f8 [2] c3 }

  condition:
    any of them
}