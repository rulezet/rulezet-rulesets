rule TTP_XOR_MULT_DOSStub_29d8 {
  strings:
    $key_29d8 = { 7d b0 [2] 09 a8 [2] 4e aa [2] 09 bb [2] 47 b7 [2] 4b bd [2] 5c b6 [2] 47 f8 [2] 7a }

  condition:
    any of them
}