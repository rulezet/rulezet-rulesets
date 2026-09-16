rule TTP_XOR_MULT_DOSStub_60d8 {
  strings:
    $key_60d8 = { 34 b0 [2] 40 a8 [2] 07 aa [2] 40 bb [2] 0e b7 [2] 02 bd [2] 15 b6 [2] 0e f8 [2] 33 }

  condition:
    any of them
}