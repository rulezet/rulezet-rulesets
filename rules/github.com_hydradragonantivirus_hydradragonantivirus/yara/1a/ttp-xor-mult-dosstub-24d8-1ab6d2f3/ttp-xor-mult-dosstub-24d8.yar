rule TTP_XOR_MULT_DOSStub_24d8 {
  strings:
    $key_24d8 = { 70 b0 [2] 04 a8 [2] 43 aa [2] 04 bb [2] 4a b7 [2] 46 bd [2] 51 b6 [2] 4a f8 [2] 77 }

  condition:
    any of them
}