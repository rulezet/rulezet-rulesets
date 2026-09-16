rule TTP_XOR_MULT_DOSStub_5cd8 {
  strings:
    $key_5cd8 = { 08 b0 [2] 7c a8 [2] 3b aa [2] 7c bb [2] 32 b7 [2] 3e bd [2] 29 b6 [2] 32 f8 [2] 0f }

  condition:
    any of them
}