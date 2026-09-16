rule TTP_XOR_MULT_DOSStub_30d8 {
  strings:
    $key_30d8 = { 64 b0 [2] 10 a8 [2] 57 aa [2] 10 bb [2] 5e b7 [2] 52 bd [2] 45 b6 [2] 5e f8 [2] 63 }

  condition:
    any of them
}