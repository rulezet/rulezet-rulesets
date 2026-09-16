rule TTP_XOR_MULT_DOSStub_7cd8 {
  strings:
    $key_7cd8 = { 28 b0 [2] 5c a8 [2] 1b aa [2] 5c bb [2] 12 b7 [2] 1e bd [2] 09 b6 [2] 12 f8 [2] 2f }

  condition:
    any of them
}