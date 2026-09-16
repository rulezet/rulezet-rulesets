rule TTP_XOR_MULT_DOSStub_64d8 {
  strings:
    $key_64d8 = { 30 b0 [2] 44 a8 [2] 03 aa [2] 44 bb [2] 0a b7 [2] 06 bd [2] 11 b6 [2] 0a f8 [2] 37 }

  condition:
    any of them
}