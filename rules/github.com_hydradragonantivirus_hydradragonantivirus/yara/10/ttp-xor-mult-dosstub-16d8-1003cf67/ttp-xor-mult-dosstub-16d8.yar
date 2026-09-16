rule TTP_XOR_MULT_DOSStub_16d8 {
  strings:
    $key_16d8 = { 42 b0 [2] 36 a8 [2] 71 aa [2] 36 bb [2] 78 b7 [2] 74 bd [2] 63 b6 [2] 78 f8 [2] 45 }

  condition:
    any of them
}