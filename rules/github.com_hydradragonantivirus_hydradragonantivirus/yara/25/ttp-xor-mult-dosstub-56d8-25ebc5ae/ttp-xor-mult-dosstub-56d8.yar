rule TTP_XOR_MULT_DOSStub_56d8 {
  strings:
    $key_56d8 = { 02 b0 [2] 76 a8 [2] 31 aa [2] 76 bb [2] 38 b7 [2] 34 bd [2] 23 b6 [2] 38 f8 [2] 05 }

  condition:
    any of them
}