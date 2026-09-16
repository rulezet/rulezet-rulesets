rule TTP_XOR_MULT_DOSStub_6cd8 {
  strings:
    $key_6cd8 = { 38 b0 [2] 4c a8 [2] 0b aa [2] 4c bb [2] 02 b7 [2] 0e bd [2] 19 b6 [2] 02 f8 [2] 3f }

  condition:
    any of them
}