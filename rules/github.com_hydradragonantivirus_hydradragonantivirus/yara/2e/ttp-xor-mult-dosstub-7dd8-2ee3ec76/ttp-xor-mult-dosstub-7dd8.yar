rule TTP_XOR_MULT_DOSStub_7dd8 {
  strings:
    $key_7dd8 = { 29 b0 [2] 5d a8 [2] 1a aa [2] 5d bb [2] 13 b7 [2] 1f bd [2] 08 b6 [2] 13 f8 [2] 2e }

  condition:
    any of them
}