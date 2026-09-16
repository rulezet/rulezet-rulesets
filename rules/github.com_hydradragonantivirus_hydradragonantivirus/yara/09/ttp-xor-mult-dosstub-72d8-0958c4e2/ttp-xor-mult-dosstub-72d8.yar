rule TTP_XOR_MULT_DOSStub_72d8 {
  strings:
    $key_72d8 = { 26 b0 [2] 52 a8 [2] 15 aa [2] 52 bb [2] 1c b7 [2] 10 bd [2] 07 b6 [2] 1c f8 [2] 21 }

  condition:
    any of them
}