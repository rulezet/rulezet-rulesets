rule TTP_XOR_MULT_DOSStub_3dd8 {
  strings:
    $key_3dd8 = { 69 b0 [2] 1d a8 [2] 5a aa [2] 1d bb [2] 53 b7 [2] 5f bd [2] 48 b6 [2] 53 f8 [2] 6e }

  condition:
    any of them
}