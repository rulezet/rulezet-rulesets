rule TTP_XOR_MULT_DOSStub_79d8 {
  strings:
    $key_79d8 = { 2d b0 [2] 59 a8 [2] 1e aa [2] 59 bb [2] 17 b7 [2] 1b bd [2] 0c b6 [2] 17 f8 [2] 2a }

  condition:
    any of them
}