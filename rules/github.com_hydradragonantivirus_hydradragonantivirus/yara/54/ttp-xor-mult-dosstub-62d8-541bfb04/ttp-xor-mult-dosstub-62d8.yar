rule TTP_XOR_MULT_DOSStub_62d8 {
  strings:
    $key_62d8 = { 36 b0 [2] 42 a8 [2] 05 aa [2] 42 bb [2] 0c b7 [2] 00 bd [2] 17 b6 [2] 0c f8 [2] 31 }

  condition:
    any of them
}