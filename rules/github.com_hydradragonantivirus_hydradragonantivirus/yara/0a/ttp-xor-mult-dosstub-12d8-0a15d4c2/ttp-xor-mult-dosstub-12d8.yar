rule TTP_XOR_MULT_DOSStub_12d8 {
  strings:
    $key_12d8 = { 46 b0 [2] 32 a8 [2] 75 aa [2] 32 bb [2] 7c b7 [2] 70 bd [2] 67 b6 [2] 7c f8 [2] 41 }

  condition:
    any of them
}