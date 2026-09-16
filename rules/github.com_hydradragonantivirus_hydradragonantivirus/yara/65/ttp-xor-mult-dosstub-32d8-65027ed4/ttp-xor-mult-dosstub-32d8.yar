rule TTP_XOR_MULT_DOSStub_32d8 {
  strings:
    $key_32d8 = { 66 b0 [2] 12 a8 [2] 55 aa [2] 12 bb [2] 5c b7 [2] 50 bd [2] 47 b6 [2] 5c f8 [2] 61 }

  condition:
    any of them
}