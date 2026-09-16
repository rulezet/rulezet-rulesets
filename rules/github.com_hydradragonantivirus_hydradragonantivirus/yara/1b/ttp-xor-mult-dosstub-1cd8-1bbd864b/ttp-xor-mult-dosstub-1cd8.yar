rule TTP_XOR_MULT_DOSStub_1cd8 {
  strings:
    $key_1cd8 = { 48 b0 [2] 3c a8 [2] 7b aa [2] 3c bb [2] 72 b7 [2] 7e bd [2] 69 b6 [2] 72 f8 [2] 4f }

  condition:
    any of them
}