rule TTP_XOR_MULT_DOSStub_c9d8 {
  strings:
    $key_c9d8 = { 9d b0 [2] e9 a8 [2] ae aa [2] e9 bb [2] a7 b7 [2] ab bd [2] bc b6 [2] a7 f8 [2] 9a }

  condition:
    any of them
}