rule TTP_XOR_MULT_DOSStub_28d8 {
  strings:
    $key_28d8 = { 7c b0 [2] 08 a8 [2] 4f aa [2] 08 bb [2] 46 b7 [2] 4a bd [2] 5d b6 [2] 46 f8 [2] 7b }

  condition:
    any of them
}