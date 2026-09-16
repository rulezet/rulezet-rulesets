rule TTP_XOR_MULT_DOSStub_38d8 {
  strings:
    $key_38d8 = { 6c b0 [2] 18 a8 [2] 5f aa [2] 18 bb [2] 56 b7 [2] 5a bd [2] 4d b6 [2] 56 f8 [2] 6b }

  condition:
    any of them
}