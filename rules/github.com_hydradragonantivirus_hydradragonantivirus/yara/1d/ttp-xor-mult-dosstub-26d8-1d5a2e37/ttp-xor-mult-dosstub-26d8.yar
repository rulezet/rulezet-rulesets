rule TTP_XOR_MULT_DOSStub_26d8 {
  strings:
    $key_26d8 = { 72 b0 [2] 06 a8 [2] 41 aa [2] 06 bb [2] 48 b7 [2] 44 bd [2] 53 b6 [2] 48 f8 [2] 75 }

  condition:
    any of them
}