rule TTP_XOR_MULT_DOSStub_08d8 {
  strings:
    $key_08d8 = { 5c b0 [2] 28 a8 [2] 6f aa [2] 28 bb [2] 66 b7 [2] 6a bd [2] 7d b6 [2] 66 f8 [2] 5b }

  condition:
    any of them
}