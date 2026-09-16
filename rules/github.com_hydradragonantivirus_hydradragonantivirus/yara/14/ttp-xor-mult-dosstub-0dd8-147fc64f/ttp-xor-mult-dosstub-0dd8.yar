rule TTP_XOR_MULT_DOSStub_0dd8 {
  strings:
    $key_0dd8 = { 59 b0 [2] 2d a8 [2] 6a aa [2] 2d bb [2] 63 b7 [2] 6f bd [2] 78 b6 [2] 63 f8 [2] 5e }

  condition:
    any of them
}