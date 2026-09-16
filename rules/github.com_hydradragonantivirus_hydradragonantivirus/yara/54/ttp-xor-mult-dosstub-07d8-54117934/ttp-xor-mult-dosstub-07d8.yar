rule TTP_XOR_MULT_DOSStub_07d8 {
  strings:
    $key_07d8 = { 53 b0 [2] 27 a8 [2] 60 aa [2] 27 bb [2] 69 b7 [2] 65 bd [2] 72 b6 [2] 69 f8 [2] 54 }

  condition:
    any of them
}