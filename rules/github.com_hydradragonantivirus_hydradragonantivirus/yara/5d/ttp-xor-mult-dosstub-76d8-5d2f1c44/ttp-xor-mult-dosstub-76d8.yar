rule TTP_XOR_MULT_DOSStub_76d8 {
  strings:
    $key_76d8 = { 22 b0 [2] 56 a8 [2] 11 aa [2] 56 bb [2] 18 b7 [2] 14 bd [2] 03 b6 [2] 18 f8 [2] 25 }

  condition:
    any of them
}