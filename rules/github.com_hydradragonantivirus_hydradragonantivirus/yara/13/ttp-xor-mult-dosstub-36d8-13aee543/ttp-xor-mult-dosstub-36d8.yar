rule TTP_XOR_MULT_DOSStub_36d8 {
  strings:
    $key_36d8 = { 62 b0 [2] 16 a8 [2] 51 aa [2] 16 bb [2] 58 b7 [2] 54 bd [2] 43 b6 [2] 58 f8 [2] 65 }

  condition:
    any of them
}