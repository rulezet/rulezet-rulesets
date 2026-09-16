rule TTP_XOR_MULT_DOSStub_49d3 {
  strings:
    $key_49d3 = { 1d bb [2] 69 a3 [2] 2e a1 [2] 69 b0 [2] 27 bc [2] 2b b6 [2] 3c bd [2] 27 f3 [2] 1a }

  condition:
    any of them
}