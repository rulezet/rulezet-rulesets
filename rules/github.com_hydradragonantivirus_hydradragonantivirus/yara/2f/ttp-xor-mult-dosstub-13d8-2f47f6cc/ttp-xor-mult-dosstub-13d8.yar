rule TTP_XOR_MULT_DOSStub_13d8 {
  strings:
    $key_13d8 = { 47 b0 [2] 33 a8 [2] 74 aa [2] 33 bb [2] 7d b7 [2] 71 bd [2] 66 b6 [2] 7d f8 [2] 40 }

  condition:
    any of them
}