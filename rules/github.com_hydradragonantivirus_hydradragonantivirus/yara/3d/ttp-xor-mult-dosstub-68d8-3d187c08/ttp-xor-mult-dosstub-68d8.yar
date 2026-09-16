rule TTP_XOR_MULT_DOSStub_68d8 {
  strings:
    $key_68d8 = { 3c b0 [2] 48 a8 [2] 0f aa [2] 48 bb [2] 06 b7 [2] 0a bd [2] 1d b6 [2] 06 f8 [2] 3b }

  condition:
    any of them
}