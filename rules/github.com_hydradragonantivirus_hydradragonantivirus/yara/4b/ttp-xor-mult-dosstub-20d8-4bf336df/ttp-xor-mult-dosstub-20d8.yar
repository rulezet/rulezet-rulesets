rule TTP_XOR_MULT_DOSStub_20d8 {
  strings:
    $key_20d8 = { 74 b0 [2] 00 a8 [2] 47 aa [2] 00 bb [2] 4e b7 [2] 42 bd [2] 55 b6 [2] 4e f8 [2] 73 }

  condition:
    any of them
}