rule TTP_XOR_MULT_DOSStub_10d8 {
  strings:
    $key_10d8 = { 44 b0 [2] 30 a8 [2] 77 aa [2] 30 bb [2] 7e b7 [2] 72 bd [2] 65 b6 [2] 7e f8 [2] 43 }

  condition:
    any of them
}