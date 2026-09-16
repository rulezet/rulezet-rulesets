rule TTP_XOR_MULT_DOSStub_3cd8 {
  strings:
    $key_3cd8 = { 68 b0 [2] 1c a8 [2] 5b aa [2] 1c bb [2] 52 b7 [2] 5e bd [2] 49 b6 [2] 52 f8 [2] 6f }

  condition:
    any of them
}