rule TTP_XOR_MULT_DOSStub_77d8 {
  strings:
    $key_77d8 = { 23 b0 [2] 57 a8 [2] 10 aa [2] 57 bb [2] 19 b7 [2] 15 bd [2] 02 b6 [2] 19 f8 [2] 24 }

  condition:
    any of them
}