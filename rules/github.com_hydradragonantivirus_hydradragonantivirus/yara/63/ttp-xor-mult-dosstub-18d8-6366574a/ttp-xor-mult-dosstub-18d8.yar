rule TTP_XOR_MULT_DOSStub_18d8 {
  strings:
    $key_18d8 = { 4c b0 [2] 38 a8 [2] 7f aa [2] 38 bb [2] 76 b7 [2] 7a bd [2] 6d b6 [2] 76 f8 [2] 4b }

  condition:
    any of them
}