rule TTP_XOR_MULT_DOSStub_44d8 {
  strings:
    $key_44d8 = { 10 b0 [2] 64 a8 [2] 23 aa [2] 64 bb [2] 2a b7 [2] 26 bd [2] 31 b6 [2] 2a f8 [2] 17 }

  condition:
    any of them
}