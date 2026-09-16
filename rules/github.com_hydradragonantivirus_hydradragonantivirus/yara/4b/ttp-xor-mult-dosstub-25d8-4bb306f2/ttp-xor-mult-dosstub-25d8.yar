rule TTP_XOR_MULT_DOSStub_25d8 {
  strings:
    $key_25d8 = { 71 b0 [2] 05 a8 [2] 42 aa [2] 05 bb [2] 4b b7 [2] 47 bd [2] 50 b6 [2] 4b f8 [2] 76 }

  condition:
    any of them
}