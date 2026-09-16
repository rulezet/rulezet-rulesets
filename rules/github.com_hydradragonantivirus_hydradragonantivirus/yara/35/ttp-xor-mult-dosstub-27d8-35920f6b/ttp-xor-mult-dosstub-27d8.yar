rule TTP_XOR_MULT_DOSStub_27d8 {
  strings:
    $key_27d8 = { 73 b0 [2] 07 a8 [2] 40 aa [2] 07 bb [2] 49 b7 [2] 45 bd [2] 52 b6 [2] 49 f8 [2] 74 }

  condition:
    any of them
}