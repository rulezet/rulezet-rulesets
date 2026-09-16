rule TTP_XOR_MULT_DOSStub_45d8 {
  strings:
    $key_45d8 = { 11 b0 [2] 65 a8 [2] 22 aa [2] 65 bb [2] 2b b7 [2] 27 bd [2] 30 b6 [2] 2b f8 [2] 16 }

  condition:
    any of them
}